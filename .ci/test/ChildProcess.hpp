#ifndef CHILDPROCESS_HPP_
#define CHILDPROCESS_HPP_

#include <sys/select.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <functional>
#include <mutex>
#include <string>
#include <sstream>
#include <system_error>
#include <thread>
#include <vector>

class ChildProcess {

public:

	// this will not work for quoted arguments
	ChildProcess( const std::string & cmd, const std::chrono::duration<unsigned, std::milli> & timeout = std::chrono::duration<unsigned, std::milli>::max() )
		:
			ChildProcess( split( cmd ), timeout )
	{
	}

	ChildProcess( const std::vector<std::string> & argv, const std::chrono::duration<unsigned, std::milli> & timeout = std::chrono::duration<unsigned, std::milli>::max() )
		:
			argv( argv ),
			deadline( std::chrono::steady_clock::now() + timeout ),
			pid( -1 ),
			exitStatus( secretSauce ),
			stdInPipe( std::array<int,2>{ -1, -1 } ),
			stdOutPipe( std::array<int,2>{ -1, -1 } ),
			stdErrPipe( std::array<int,2>{ -1, -1 } ),
			cancelSock( std::array<int,2>{ -1, -1 } )
	{
		init();
	}

	~ChildProcess() {
		kill();
		fini();
	}

	static std::vector<std::string> split( const std::string & text ) {
		std::istringstream iss(text);
		std::vector<std::string> results(std::istream_iterator<std::string>{iss},
		                                 std::istream_iterator<std::string>());
		return results;
	}

	static std::string trim( std::string s ) {
		for( ; s.size() > 0 && ::isspace( s[ s.size() - 1 ] ); ) {
			s = s.substr( 0, s.size() - 1 );
		}
		for( ; s.size() > 0 && ::isspace( s[ 0 ] ); ) {
			s = s.substr( 1 );
		}
		if ( 1 == s.size() && ::isspace( s[ 0 ] ) ) {
			s = "";
		}
		return s;
	}

	/**
	 * Write a string to the standard input of the child process
	 *
	 * This call writes the string pointed to by @str to the child process.
	 *
	 * @param str the string to write to the child process
	 */
	void putStdIn( const std::string & str ) {
		::write( stdInPipe[ PIPE_WRITE ], str.c_str(), str.size() );
	}

	/**
	 * Return a string containing the standard output from the child process
	 *
	 * This call returns a string containing the contents of stdout from the
	 * child process since the last time getStdOut() was called.
	 *
	 * If getStdOut() was never called, then it returns a string containing
	 * the contents of stdout from the child process since the process
	 * began execution.
	 *
	 * @return the standard output of the child process
	 */
	std::string getStdOut() {
		std::lock_guard<std::mutex> lock( stdOutMutex );
		std::string r;
		std::swap(r, stdOut);
		return r;
	}

	/**
	 * Return a string containing the standard error from the child process
	 *
	 * This call returns a string containing the contents of stderr from the
	 * child process since the last time getStdErr() was called.
	 *
	 * If getStdErr() was never called, then it returns a string containing
	 * the contents of stderr from the child process since the process
	 * began execution.
	 *
	 * @return the standard error of the child process
	 */
	std::string getStdErr() {
		std::lock_guard<std::mutex> lock( stdErrMutex );
		std::string r;
		std::swap(r, stdErr);
		return r;
	}

	/**
	 * Get the process ID of the child process
	 *
	 * @return the process ID of the child process if the child process exists
	 * @return (pid_t)-1 if the child process does not exist
	 */
	::pid_t getPid() {
		return pid;
	}

	/**
	 * Determine whether the child process is running
	 *
	 * @return true  if the child is running
	 * @return false if the child is not running
	 */
	bool isRunning() {
		return 0 == ::kill( pid, 0 );
	}

	/**
	 * Get the exit status of the child process
	 *
	 * Note, this call will block until the child process either exits or is
	 * otherwise terminated.
	 *
	 * @return the exit status of the child process
	 */
	int getExitStatus() {

		std::lock_guard<std::mutex> lock( exitStatusMutex );

		if ( exitStatus == secretSauce ) {
			::siginfo_t info;
			int r;
			r = ::waitid( ::P_PID, ::id_t( pid ), & info, WEXITED );
			if ( -1 == r ) {
				throw std::system_error( errno, std::system_category(), "waitid" );
			}
			exitStatus = info.si_status;
			pid = -1;
		}

		return exitStatus;
	}

	/**
	 * Terminate the child process
	 *
	 * This call terminates the child process and cleans up all associated
	 * resources.
	 *
	 * First, If the child process is not running, this call simply returns.
	 *
	 * Next, SIGTERM is issued.
	 *
	 * Lastly, if the process still hasn't exited after 3 seconds, then SIGKILL
	 * is issued.
	 */
	void kill() {

		std::lock_guard<std::mutex> lock( killMutex );

		if ( ! isRunning() ) {
			return;
		}

		int r;

		// break out of the select(2) loop in monitorThreadFunction()
		r = ::write( cancelSock[ PIPE_WRITE ], "x", 1 );
		if ( -1 == r ) {
			throw std::system_error( errno, std::system_category(), "write" );
		}

		if ( -1 != pid ) {

			r = ::kill( pid, SIGTERM );
			if ( -1 == r ) {
				throw std::system_error( errno, std::system_category(), "kill(" + std::to_string( int( pid ) ) + ", SIGTERM)" );
			}

			for( int i = 3; i; i-- ) {
				if ( ! isRunning() ) {
					break;
				}
				using namespace std::chrono_literals;
				std::this_thread::sleep_for(1s);
			}

			if ( isRunning() ) {
				r = ::kill( pid, SIGKILL );
				if ( -1 == r ) {
					throw std::system_error( errno, std::system_category(), "kill(" + std::to_string( int( pid ) ) + ", SIGKILL)" );
				}
			}
			pid = -1;
		}

		r = ::write( cancelSock[ PIPE_WRITE ], "x", 1 );
		if ( -1 == r ) {
			throw std::system_error( errno, std::system_category(), "write" );
		}
	}

protected:
	void init() {

		argv[ 0 ] = trim( argv[ 0 ] );

		int r;

		const std::vector<int *> pipeArrays = {
			stdInPipe.begin(),
			stdOutPipe.begin(),
			stdErrPipe.begin(),
		};

		for( auto pipes: pipeArrays ) {
			r = ::pipe( pipes );
			if ( -1 == r ) {
				fini();
				throw std::system_error( errno, std::system_category(), "pipe" );
			}
		}

		// cancellation socket (to interrupt select(2))
		r = socketpair( AF_UNIX, SOCK_STREAM, 0, cancelSock.begin() );
		if ( -1 == r ) {
			fini();
			throw std::system_error( errno, std::system_category(), "socketpair" );
		}

		pid = fork();
		if ( -1 == pid ) {
			fini();
			throw std::system_error( errno, std::system_category(), "fork" );
		}
		if ( pid > 0 ) {
		    // parent process. close unused file descriptors
		    ::close( stdInPipe[ PIPE_READ ] );
		    ::close( stdOutPipe[ PIPE_WRITE ] );
		    ::close( stdErrPipe[ PIPE_WRITE ] );

			mon = std::thread( std::bind( & ChildProcess::monitorThreadFunction, this ) );
		    return;
		}

		std::array<std::pair<int,int>,3> redirects = {{
			{ stdInPipe[ PIPE_READ ], STDIN_FILENO },
			{ stdOutPipe[ PIPE_WRITE ], STDOUT_FILENO },
			{ stdErrPipe[ PIPE_WRITE ], STDERR_FILENO },
		}};

		for( auto redir: redirects ) {
			r = dup2( redir.first, redir.second );
			if ( -1 == r ) {
				fini();
				throw std::system_error( errno, std::system_category(), "dup2" );
			}
		}

		// execute command

		const std::vector<std::string> pathPatterns = {
			"/",
			".",
			"./",
			"../"
		};

		// use execvp() when argv[0] does *not* begin with a pathPattern
		// because execvp() uses the path environment variable to automatically
		// find the executable
		bool useExecvp = true;
		for( auto & p: pathPatterns ) {
			if ( argv[ 0 ].substr( 0, p.size() ) == p ) {
				useExecvp = false;
			}
		}

		std::vector<char *> _argv;
		for( auto & a: argv ) {
			_argv.push_back( (char *)a.c_str() );
		}
		_argv.push_back( NULL );

		if ( useExecvp ) {
			::execvp( argv[ 0 ].c_str(), & _argv[ 0 ] );
		} else {
			::execv( argv[ 0 ].c_str(), & _argv[ 0 ] );
		}

		// should not get here, but if we do, exit with the errno value
		::exit( errno );
	}

	void fini() {

		int r;

		std::vector<int*> pipefds = {
			& stdInPipe[ PIPE_READ ],
			& stdInPipe[ PIPE_WRITE ],
			& stdOutPipe[ PIPE_READ ],
			& stdOutPipe[ PIPE_WRITE ],
			& stdErrPipe[ PIPE_READ ],
			& stdErrPipe[ PIPE_WRITE ],
			& cancelSock[ PIPE_READ ],
			& cancelSock[ PIPE_WRITE ],
		};

		for( auto fd: pipefds ) {
			if ( -1 == *fd ) {
				continue;
			}
			::close( *fd );
			*fd = -1;
		}

		mon.join();
	}

	void monitorThreadFunction() {
		fd_set rfds;
		fd_set efds;
		std::array<uint8_t,64> buff;

		for( ;; ) {
			FD_ZERO( &rfds );
			FD_ZERO( &efds );

			int maxfd = std::max({
				stdOutPipe[ PIPE_READ ],
				stdErrPipe[ PIPE_READ ],
				cancelSock[ PIPE_READ ]
			});

			FD_SET( stdOutPipe[ PIPE_READ ], & rfds );
			FD_SET( stdOutPipe[ PIPE_READ ], & efds );
			FD_SET( stdErrPipe[ PIPE_READ ], & rfds );
			FD_SET( stdErrPipe[ PIPE_READ ], & efds );
			FD_SET( cancelSock[ PIPE_READ ], & rfds );
			FD_SET( cancelSock[ PIPE_READ ], & efds );

			struct timeval to = {
				.tv_sec = 0,
				.tv_usec = 250000,
			};

			int r = ::select( maxfd + 1, & rfds, nullptr, & efds, & to );
			if ( 0 == r ) {
				// timeout
			}
			if ( -1 == r ) {
				if ( EBADF == errno ) {
					break;
				}
				throw std::system_error( errno, std::system_category(), "select" );
			}
			if ( FD_ISSET( stdOutPipe[ PIPE_READ ], & rfds ) ) {
				std::lock_guard<std::mutex> lock( stdOutMutex );
				r = ::read( stdOutPipe[ PIPE_READ ], buff.begin(), buff.size() );
				if ( -1 == r ) {
					if ( EBADF == errno ) {
						break;
					}
					throw std::system_error( errno, std::system_category(), "read" );
				}
				stdOut += std::string( buff.begin(), buff.begin() + r );
			}
			if ( FD_ISSET( stdErrPipe[ PIPE_READ ], & rfds ) ) {
				std::lock_guard<std::mutex> lock( stdErrMutex );
				r = ::read( stdErrPipe[ PIPE_READ ], buff.begin(), buff.size() );
				if ( -1 == r ) {
					if ( EBADF == errno ) {
						break;
					}
					throw std::system_error( errno, std::system_category(), "read" );
				}
				stdErr += std::string( buff.begin(), buff.begin() + r );
			}
			if (
				false
				|| FD_ISSET( stdOutPipe[ PIPE_READ ], & efds )
				|| FD_ISSET( stdErrPipe[ PIPE_READ ], & efds )
				|| FD_ISSET( cancelSock[ PIPE_READ ], & efds )
				|| FD_ISSET( cancelSock[ PIPE_READ ], & rfds )
			) {
				break;
			}
			if ( ! isRunning() ) {
				break;
			}
			if ( std::chrono::steady_clock::now() >= deadline ) {
				kill();
				break;
			}
		}
	}

	enum {
		PIPE_READ,
		PIPE_WRITE,
	};

	const int secretSauce = 0x5ec2e7;

	std::mutex stdOutMutex;
	std::string stdOut;
	std::mutex stdErrMutex;
	std::string stdErr;

	std::vector<std::string> argv;

	::pid_t pid;
	std::mutex killMutex;

	int exitStatus;
	std::mutex exitStatusMutex;

	std::array<int,2> stdInPipe;
	std::array<int,2> stdOutPipe;
	std::array<int,2> stdErrPipe;
	std::array<int,2> cancelSock;

	std::thread mon;

	std::chrono::time_point<std::chrono::steady_clock> deadline;
};

#endif /* CHILDPROCESS_HPP_ */
