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

all: $(KERNEL)/vmlinux $(BUSYBOX)/busybox $(DROPBEAR)/dropbear

# rules to build the Linux kernel
$(KERNEL_ARCHIVE):
	KERNEL_TMP="`mktemp -p .`"; \
	curl -L "$(KERNEL_URL)" -o $$KERNEL_TMP; \
	if [ $$? -ne 0 ]; then \
		rm -f $$KERNEL_TMP; exit 1; \
	fi; \
	mv $$KERNEL_TMP $@

$(KERNEL): $(KERNEL_ARCHIVE)
	KERNEL_TMP="`mktemp -d -p .`" && tar xpzf $(KERNEL_ARCHIVE) -C "$$KERNEL_TMP"; \
	if [ $$? -ne 0 ]; then \
		rm -Rf $$KERNEL_TMP; exit 1; \
	else \
		mv $$KERNEL_TMP/$(KERNEL) .; rm -Rf $$KERNEL_TMP; \
	fi

$(KERNEL)/.config: $(KERNEL_CONFIG) $(KERNEL)
	cp $(KERNEL_CONFIG) $(KERNEL)/.config

$(KERNEL)/vmlinux: $(KERNEL)/.config
	$(MAKE) -C $(KERNEL) vmlinux

# rules to build busybox
$(BUSYBOX_ARCHIVE):
	BUSYBOX_TMP="`mktemp -p .`"; \
	curl -L "$(BUSYBOX_URL)" -o $$BUSYBOX_TMP; \
	if [ $$? -ne 0 ]; then \
		rm -f $$BUSYBOX_TMP; exit 1; \
	fi; \
	mv $$BUSYBOX_TMP $@

$(BUSYBOX): $(BUSYBOX_ARCHIVE)
	BUSYBOX_TMP="`mktemp -d -p .`" && tar xpjf $(BUSYBOX_ARCHIVE) -C "$$BUSYBOX_TMP"; \
	if [ $$? -ne 0 ]; then \
		rm -Rf $$BUSYBOX_TMP; exit 1; \
	else \
		mv $$BUSYBOX_TMP/$(BUSYBOX) .; rm -Rf $$BUSYBOX_TMP; \
	fi

$(BUSYBOX)/.config: $(BUSYBOX_CONFIG) $(BUSYBOX)
	cp $(BUSYBOX_CONFIG) $(BUSYBOX)/.config

$(BUSYBOX)/busybox: $(BUSYBOX)/.config
	$(MAKE) -C $(BUSYBOX)

# rules to build dropbear
$(DROPBEAR_ARCHIVE):
	DROPBEAR_TMP="`mktemp -p .`"; \
	curl -L "$(DROPBEAR_URL)" -o $$DROPBEAR_TMP; \
	if [ $$? -ne 0 ]; then \
		rm -f $$DROPBEAR_TMP; exit 1; \
	fi; \
	mv $$DROPBEAR_TMP $@

$(DROPBEAR): $(DROPBEAR_ARCHIVE)
	DROPBEAR_TMP="`mktemp -d -p .`" && tar xpjf $(DROPBEAR_ARCHIVE) -C "$$DROPBEAR_TMP"; \
	if [ $$? -ne 0 ]; then \
		rm -Rf $$DROPBEAR_TMP; exit 1; \
	else \
		mv $$DROPBEAR_TMP/$(DROPBEAR) .; rm -Rf $$DROPBEAR_TMP; \
	fi

$(DROPBEAR)/dropbear: $(DROPBEAR)
	cd $(DROPBEAR) && ./configure --enable-static
	$(MAKE) -C $(DROPBEAR)

clean:
	rm -Rf $(CLEANFILES)

