#include "QemuSystemTestFixture.hpp"

using namespace std;

TEST_F( QemuSystemTestFixture, Null ) {
}

TEST_F( QemuSystemTestFixture, SshHelloWorld ) {
	string greeting( "Hello, world!" );
	vector<string> args = {
		"ssh",
		"-p", "2222",
		"-oStrictHostKeyChecking=no",
		"root@localhost",
		"echo '" + greeting + "'",
	};
	ChildProcess hi( args );

	int expected_int;
	int actual_int;

	string expected_string;
	string actual_string;

	expected_int = 0;
	actual_int = hi.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	expected_string = greeting + "\n";
	actual_string = hi.getStdOut();
	EXPECT_EQ( actual_string, expected_string );
}

TEST_F( QemuSystemTestFixture, FiveXSshHelloWorld ) {
	string greeting( "Hello, world!" );
	vector<string> args = {
		"ssh",
		"-p", "2222",
		"-oStrictHostKeyChecking=no",
		"root@localhost",
		"echo '" + greeting + "'",
	};

	int expected_int;
	int actual_int;

	string expected_string;
	string actual_string;

	for( int i = 0; i < 5; i++ ) {
		ChildProcess hi( args );

		expected_int = 0;
		actual_int = hi.getExitStatus();
		EXPECT_EQ( actual_int, expected_int );

		expected_string = greeting + "\n";
		actual_string = hi.getStdOut();
		EXPECT_EQ( actual_string, expected_string );
	}
}

