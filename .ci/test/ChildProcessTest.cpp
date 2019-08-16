#include <gtest/gtest.h>

#include "ChildProcess.hpp"

/*
 * Test that demonstrates failure with an empty command
 */
TEST( ChildProcess, EmptyCommand ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( "" );

	ChildProcess cp( argv );
	expected_int = ENOENT;
	actual_int = cp.getExitStatus();

	EXPECT_EQ( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * Test that demonstrates failure with an invalid command
 */
TEST( ChildProcess, WhitespaceOnlyCommand ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( " \t  \t\t " );

	ChildProcess cp( argv );
	expected_int = ENOENT;
	actual_int = cp.getExitStatus();

	EXPECT_EQ( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * Test that demonstrates failure when the executable does not exist
 */
TEST( ChildProcess, NonexistentProgram ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( "/foo/bar" );

	ChildProcess cp( argv );
	expected_int = ENOENT;
	actual_int = cp.getExitStatus();

	EXPECT_EQ( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * This 'true' command (no stdout, just exit value of 0)
 */
TEST( ChildProcess, True ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( "true" );

	ChildProcess cp( argv );

	expected_int = 0;
	actual_int = cp.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * This 'false' command (no stdout, just exit value of 1)
 */
TEST( ChildProcess, False ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( "false" );

	ChildProcess cp( argv );

	expected_int = EXIT_FAILURE;
	actual_int = cp.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * This test puts some data on stdout
 */
TEST( ChildProcess, EchoHelloWorld ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::string greeting( "Hello, world!" );

	std::vector<std::string> argv;
	argv.push_back( "echo" );
	argv.push_back( greeting );

	ChildProcess cp( argv );

	expected_int = 0;
	actual_int = cp.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	expected_string = greeting + "\n";
	actual_string = cp.getStdOut();
	EXPECT_EQ( actual_string, expected_string );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}

/*
 * This test ensures that a deadline of 1s is observed for executing the command
 */
/*
TEST( ChildProcess, Yes ) {

	int expected_int;
	int actual_int;
	std::string expected_string;
	std::string actual_string;

	std::vector<std::string> argv;
	argv.push_back( "yes" );

	using namespace std::chrono_literals;
	ChildProcess cp( argv, 500ms );

	// The 'yes' command is designed to run forever, and so we will definitely
	// hit the 500ms deadline and kill the program. When the process stops due to
	// a signal, the return value is the signal that stopped it.
	expected_int = SIGTERM;
	actual_int = cp.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	// count the number of y's in stdout, and make sure it's more than this
	expected_int = 1000;
	actual_int = 0;
	for( auto & c: cp.getStdOut() ) {
		if ( 'y' == c ) {
			actual_int++;
		}
	}
	EXPECT_GT( actual_int, expected_int );

	expected_string = "";
	actual_string = cp.getStdErr();
	EXPECT_EQ( actual_string, expected_string );
}
*/
