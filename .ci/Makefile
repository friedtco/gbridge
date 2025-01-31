.PHONY: all clean distclean qemu check

CXX = g++
CXXFLAGS :=
CXXFLAGS += -fPIC
CXXFLAGS += -std=c++14
CXXFLAGS += -O0 -g

# these are known working architectures for integration testing in the CI environment
SUPPORTED_ARCHES = x86_64

ARCH = $(shell uname -m)

ifeq ($(SUPPORTED_ARCHES),$(filter-out,$(ARCH),$(SUPPORTED_ARCHES)))
$(error Architecture $(ARCH) is not yet supported / known working for integration testing)
endif

CLEANFILES :=

# variables for building BusyBox
BUSYBOX_VER      = 1.30.1
BUSYBOX          = busybox-$(BUSYBOX_VER)
BUSYBOX_ARCHIVE  = $(BUSYBOX).tar.bz2
BUSYBOX_URL      = https://busybox.net/downloads/$(BUSYBOX_ARCHIVE)
DISTCLEANFILES  += $(BUSYBOX) $(BUSYBOX_ARCHIVE)

# variables for building Dropbear
DROPBEAR_VER     = 2019.78
DROPBEAR_URL     = https://matt.ucc.asn.au/dropbear/releases/dropbear-$(DROPBEAR_VER).tar.bz2
DROPBEAR         = dropbear-$(DROPBEAR_VER)
DROPBEAR_ARCHIVE = $(DROPBEAR).tar.bz2
DISTCLEANFILES  += $(DROPBEAR) $(DROPBEAR_ARCHIVE)

# variables for building gbridge
GBRIDGE = gbridge-build

# variables for building initramfs
INITRAMFS        = initramfs
DISTCLEANFILES  += $(INITRAMFS)

# variables for building the Linux kernel
KERNEL_VER       = 5.1
KERNEL_URL       = https://github.com/torvalds/linux/archive/v$(KERNEL_VER).tar.gz
KERNEL           = linux-$(KERNEL_VER)
KERNEL_CONFIG    = $(KERNEL).config
KERNEL_ARCHIVE   = $(KERNEL).tar.gz
DISTCLEANFILES  += $(KERNEL) $(KERNEL_ARCHIVE)

CPP_SRC          = $(shell find test/ -name '*Test.cpp')
CPP_HDR          = $(shell find test/ -name '*.hpp')
TEST             = $(CPP_SRC:.cpp=)
CLEANFILES      += $(TEST)

#all: $(KERNEL)/arch/$(ARCH)/boot/bzImage
all: $(TEST)

# rules to build busybox
$(BUSYBOX_ARCHIVE):
	curl -L "$(BUSYBOX_URL)" -o $@

$(BUSYBOX): $(BUSYBOX_ARCHIVE)
	tar xpjf $<

$(BUSYBOX)/busybox: $(BUSYBOX)
	$(MAKE) -C $< defconfig
	echo 'CONFIG_STATIC=y' >> $(BUSYBOX)/.config
	$(MAKE) -C $<

# rules to build dropbear
$(DROPBEAR_ARCHIVE):
	curl -L "$(DROPBEAR_URL)" -o $@

$(DROPBEAR): $(DROPBEAR_ARCHIVE)
	tar xpjf $<

$(DROPBEAR)/dropbear: $(DROPBEAR)
	cd $< && patch -p1 < ../dropbear-all-root-login.patch
	cd $< && ./configure --enable-static
	$(MAKE) -C $<

$(DROPBEAR)/scp: $(DROPBEAR)/dropbear
	$(MAKE) -C $(dir $<) $(notdir $@)

# rules to build gbridge
$(GBRIDGE)/gbridge: $(KERNEL)
	cd .. && autoreconf --force --install
	mkdir -p $(dir $@)
	cd $(dir $@) && GBDIR=../$(KERNEL)/drivers/staging/greybus LDFLAGS="-static" ../../configure
	cd $(dir $@) && $(MAKE)

# rules to build initramfs
$(INITRAMFS): $(BUSYBOX)/busybox $(DROPBEAR)/dropbear $(DROPBEAR)/scp $(GBRIDGE)/gbridge busybox-rcS.sh Makefile
	mkdir -p \
		$@/bin \
		$@/sbin \
		$@/dev \
		$@/etc/init.d \
		$@/etc/dropbear \
		$@/proc \
		$@/root \
		$@/sys \
		$@/usr/bin \
		$@/usr/sbin \
		$@/usr/share/udhcpc \
		$@/var/run
	echo 'root::0:0:root:/root:/bin/sh' > $@/etc/passwd
	echo 'root::0:root' > $@/etc/group
	cd $@/dev && if [ ! -e console ]; then sudo mknod -m 600 console c 5 1; fi
	cd $@/dev && if [ ! -e null ]; then sudo mknod -m 666 null c 1 3; fi
	cd $@/bin && ln -sf /bin/busybox sh
	cd $@ && ln -sf /bin/busybox init
	cp $(BUSYBOX)/busybox $@/bin
	cp $(BUSYBOX)/examples/udhcp/simple.script $@/usr/share/udhcpc/default.script
	cp $(DROPBEAR)/dropbear $@/bin
	cp $(DROPBEAR)/scp $@/bin
	cp busybox-rcS.sh $@/etc/init.d/rcS
	chmod +x $@/etc/init.d/rcS
	cp $(GBRIDGE)/gbridge $@/bin/gbridge
	touch $@

# rules to build the Linux kernel
$(KERNEL_ARCHIVE):
	curl -L "$(KERNEL_URL)" -o $@

$(KERNEL): $(KERNEL_ARCHIVE)
	tar xpzf $<
	cd $@ && patch -p1 < ../$(KERNEL)-greybus-netlink.patch
	touch $@

$(KERNEL)/arch/$(ARCH)/boot/bzImage: $(KERNEL) $(KERNEL_CONFIG) $(INITRAMFS)
	cp $(KERNEL_CONFIG) $</.config
	$(MAKE) -C $< $(notdir $@)
	touch $@

$(INITRAMFS_ARCHIVE): $(INITRAMFS)
	cd $< && find . -print0 | cpio --create --format=newc | gzip -9 > ../$@

qemu: $(KERNEL)/arch/$(ARCH)/boot/bzImage
	qemu-system-x86_64 \
		-nographic \
		-cpu host \
		-enable-kvm \
		-netdev user,id=eth0,hostfwd=tcp::2222-:22,hostfwd=tcp::12345-:2345,hostfwd=tcp::36484-:18242 \
		-device e1000,netdev=eth0 \
		-kernel $(KERNEL)/arch/$(ARCH)/boot/bzImage \
		-append "console=ttyS0 root=/dev/ram0"

clean:
	rm -Rf $(CLEANFILES)

distclean:
	rm -Rf $(CLEANFILES) $(DISTCLEANFILES)

%: %.cpp $(CPP_HDR)
	$(CXX) $(CXXFLAGS) -I../../ -I../ `pkg-config --cflags gtest` -o $@ $< `pkg-config --libs gtest gtest_main`

check: $(TEST)
	for i in $(TEST); do \
		./$$i; \
	done
