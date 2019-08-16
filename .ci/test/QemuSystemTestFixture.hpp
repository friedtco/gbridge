#ifndef QEMU_SYSTEM_TEST_FIXTURE_HPP_
#define QEMU_SYSTEM_TEST_FIXTURE_HPP_

#include <memory>
#include <vector>
#include <string>

#include <gtest/gtest.h>

#include "ChildProcess.hpp"

class QemuSystemTestFixture : public ::testing::Test {
public:
	QemuSystemTestFixture() {}
	~QemuSystemTestFixture() {}

protected:
	virtual void SetUp() override {
		std::vector<std::string> args = {
			"qemu-system-x86_64",
			"-nographic",
			"-cpu", "host",
			"-enable-kvm",
			"-netdev", "user,id=eth0,hostfwd=tcp::2222-:22,hostfwd=tcp::12345-:2345",
			"-device", "e1000,netdev=eth0",
			"-kernel", "linux-5.1/arch/x86_64/boot/bzImage",
			"-append", "\"console=ttyS0 root=/dev/ram0\"",
		};

		using namespace std::chrono_literals;
		qemuChildProcess = std::make_shared<ChildProcess>( args, 10s );
		std::cerr << "Child process has PID: " << int(qemuChildProcess->getPid()) << std::endl;
		for(
			std::string out = qemuChildProcess->getStdOut();
			qemuChildProcess->isRunning() && std::string::npos == out.find( "dropbear" );
			out = qemuChildProcess->getStdOut()
		) {
			std::this_thread::sleep_for( 250ms );
		}
	}
	virtual void TearDown() override {
		qemuChildProcess->kill();
		qemuChildProcess = nullptr;
	}

	std::shared_ptr<ChildProcess> qemuChildProcess;
};

#endif /* QEMU_SYSTEM_TEST_FIXTURE_HPP_ */
