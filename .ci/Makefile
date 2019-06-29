.PHONY: all clean check

# these are known working architectures for integration testing in the CI environment
SUPPORTED_ARCHES = x86_64

ARCH = $(shell uname -a)

ifeq ($(SUPPORTED_ARCHES),$(filter-out,$(ARCH),$(SUPPORTED_ARCHES)))
$(error Architecture $(ARCH) is not yet supported / known working for integration testing)
endif

CLEANFILES :=

# variables for building the Linux kernel
KERNEL_VER     = 5.1
KERNEL_URL     = https://github.com/torvalds/linux/archive/v$(KERNEL_VER).tar.gz
KERNEL         = linux-$(KERNEL_VER)
KERNEL_CONFIG  = $(KERNEL).config
KERNEL_ARCHIVE = $(KERNEL).tar.gz
CLEANFILES     += $(KERNEL) $(KERNEL_ARCHIVE)

# variables for building BusyBox
BUSYBOX_VER     = 1.30.1
BUSYBOX         = busybox-$(BUSYBOX_VER)
BUSYBOX_ARCHIVE = $(BUSYBOX).tar.bz2
BUSYBOX_URL     = https://busybox.net/downloads/$(BUSYBOX_ARCHIVE)
BUSYBOX_CONFIG  = busybox-$(BUSYBOX_VER).config
CLEANFILES      += $(BUSYBOX) $(BUSYBOX_ARCHIVE)

# variables for building Dropbear
DROPBEAR_VER     = 2019.78
DROPBEAR_URL     = https://matt.ucc.asn.au/dropbear/releases/dropbear-$(DROPBEAR_VER).tar.bz2
DROPBEAR         = dropbear-$(DROPBEAR_VER)
DROPBEAR_ARCHIVE = $(DROPBEAR).tar.bz2
CLEANFILES      += $(DROPBEAR) $(DROPBEAR_ARCHIVE)

# variables for building initramfs
INITRAMFS          = initramfs
INITRAMFS_ARCHIVE  = initramfs.cpio.gz
CLEANFILES        += $(INITRAMFS) $(INITRAMFS_ARCHIVE)

all: $(KERNEL)/arch/x86_64/boot/bzImage $(INITRAMFS_ARCHIVE)

# rules to build the Linux kernel
$(KERNEL_ARCHIVE):
	curl -L "$(KERNEL_URL)" -o $@

$(KERNEL): $(KERNEL_ARCHIVE)
	tar xpzf $<

$(KERNEL)/.config: $(KERNEL_CONFIG) $(KERNEL)
	cp $< $@

$(KERNEL)/arch/x86_64/boot/bzImage: $(KERNEL) $(KERNEL)/.config
	$(MAKE) -C $< $(notdir $@)

# rules to build busybox
$(BUSYBOX_ARCHIVE):
	curl -L "$(BUSYBOX_URL)" -o $@

$(BUSYBOX): $(BUSYBOX_ARCHIVE)
	tar xpjf $<

$(BUSYBOX)/.config: $(BUSYBOX_CONFIG) $(BUSYBOX)
	cp $< $@

$(BUSYBOX)/busybox: $(BUSYBOX) $(BUSYBOX)/.config
	$(MAKE) -C $<

# rules to build dropbear
$(DROPBEAR_ARCHIVE):
	curl -L "$(DROPBEAR_URL)" -o $@

$(DROPBEAR): $(DROPBEAR_ARCHIVE)
	tar xpjf $<

$(DROPBEAR)/dropbear: $(DROPBEAR)
	cd $< && ./configure --enable-static
	$(MAKE) -C $<

# rules to build initramfs
$(INITRAMFS): $(BUSYBOX)/busybox $(DROPBEAR)/dropbear
	mkdir -p \
		$@/bin \
		$@/sbin \
		$@/etc/init.d \
		$@/proc \
		$@/sys \
		$@/usr/bin \
		$@/usr/sbin \
		$@/usr/share/udhcpc
	cd $@/bin && ln -sf /bin/busybox sh
	cd $@ && ln -sf /bin/busybox init
	cp $(BUSYBOX)/busybox $@/bin
	cp $(BUSYBOX)/examples/udhcp/simple.script $@/usr/share/udhcpc/default.script
	cp busybox-rcS.sh $@/etc/init.d/rcS
	chmod +x $@/etc/init.d/rcS
	cp $(DROPBEAR)/dropbear $@/bin

$(INITRAMFS_ARCHIVE): $(INITRAMFS)
	cd $< && find . -print0 | cpio --create --format=newc | gzip -9 > ../$@

qemu: $(INITRAMFS_ARCHIVE) $(KERNEL)/arch/x86_64/boot/bzImage
	qemu-system-x86_64 \
		-nographic \
		-cpu Nehalem \
		-kernel $(KERNEL)/arch/x86_64/boot/bzImage \
		-initrd initramfs.cpio.gz \
		-append "console=ttyS0 init=/init root=/dev/ram"

clean:
	rm -Rf $(CLEANFILES)
