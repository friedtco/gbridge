[![Build Status](https://travis-ci.com/friedtco/gbridge.svg?token=tYzdCS7A2DzjyBybyBVm&branch=feature/1/gbridge-automated-build)](https://travis-ci.com/friedtco/gbridge)

GBridge (Greybus Bridge)

Greybus is a protocol layer for UniPro bus.
It was supposed to be used by modular phones to control modules.

GBridge is an application that can be used to support other bus / network,
such as TCP/IP or bluetooth. 

I) SVC
The SVC take a central piece in Greybus.
It is in charge of module hot plug / hot unplug detection,
create / destroy connections, etc.
In modular phones, the SVC is a micro-controller but here,
we don't have a micro-controller to detect modules,
so we have to simulate it.

SVC protocol has been made for UniPro.
Most of the SVC operations are useless or not adapted for non UniPro modules.
The current implementation of SVC protocol only implements the mandatory
operations though some of them are not correctly implemented
(such as DME operations).

II) Netlink
GBridge is using netlink to communicate with Greybus.
Currently, netlink is only used to transmit Greybus operations,
but it's planned to use it to control Greybus when SVC protocol is not adapted.

II) Controller
The controller is actually the link between the SVC, netlink and all the
modules.
The controller is actually handling some operations made by SVC in phones,
such as modules detection and connection.

a) Bluetooth controller
The Bluetooth controller scans continuously to detect new bluetooth module.
When a Bluetooth module with the "GREYBUS" string in its name show up,
the controller will generate an hotplug event and create a connection.
Currently, the controller open a RFCOMM socket that is not available for BLE.
It's planned to use L2CAP instead of RFCOMM to support both Bluetooth and BLE.
Because RFCOMM doesn't have any notion of channel, the controller use the
padding bytes in operation header to store the cport number.

b) TCP/IP
The controller use avahi to detect a new module.
The controller only add module with a "_greybus._tcp" service.
Avahi is currently the easiest way to detect a new device on the host but
may be it is not adapted for the small microcontrollers used for IOT.
The controller will open one socket per cport, so there no need to store
the cport number number in Greybus operation.
The connection is initiated by the controller, so the module must open
a socket for each cport to connect.

IV) Build
a) Greybus
To build gbridge, you will need Greybus sources.
git clone https://github.com/anobli/greybus.git -b gb_netlink
cd greybus
make && sudo make install

b) gbridge
git clone https://github.com/anobli/gbridge.git
cd gbridge
autoconf
automake --add-missing
GBDIR=path/to/greybus/ ./configure
make

V) Usage
a) Kernel
First, you need to load Greybus module:
modprobe gb_netlink # will also load greybus module

After, you should load modules for protocols you want to use:
modprobe gb_phy
modprobe gb_loopback
and so on.

b) gbridge
./gbridge
That's it. Nothing else to do!
gbridge will detect new modules on bluetooth or TCP/IP and then
it will send hotplug event to Greybus.
Then, Greybus will try to connect to module, get manifest and create
the appropriate devices and entries in sysfs.
