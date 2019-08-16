#include "QemuSystemTestFixture.hpp"

using namespace std;

TEST_F( QemuSystemTestFixture, Null ) {
}

TEST_F( QemuSystemTestFixture, SshHelloWorld ) {
	int expected_int;
	int actual_int;
	string expected_string;
	string actual_string;

	vector<string> args = {
		"ssh",
		"-p", "2222",
		"-oStrictHostKeyChecking=no",
		"root@localhost",
		"echo 'Hello, world!'",
	};
	ChildProcess hi( args );

	expected_int = 0;
	actual_int = hi.getExitStatus();
	EXPECT_EQ( actual_int, expected_int );

	expected_string = "Hello, world!\n";
	actual_string = hi.getStdOut();
	EXPECT_EQ( actual_string, expected_string );
}
