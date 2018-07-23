CC		= $(CROSS_COMPILE)gcc
LD		= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH		= x86_64

UDK		?= /media/psf/Projects/linux/UDK2015/Build/Include
UDKINC		:= -I$(UDK)/MdePkg/Include -I$(UDK)/MdeModulePkg/Include -I$(UDK)/IntelFrameworkPkg/Include -I$(UDK)/IntelFrameworkModulePkg/Include -I$(UDK)/CryptoPkg/Include -I$(UDK)/MdePkg/Include/X64
UDKLIBBASE	?= /media/psf/Projects/linux/UDK2015/Build
UDKLIB		:= $(UDKLIBBASE)/Release64
UDKLIBS		= --start-group $(UDKLIB)/BasePeCoffLib.lib $(UDKLIB)/PeCoffExtraActionLibNull.lib $(UDKLIB)/BaseCacheMaintenanceLib.lib $(UDKLIB)/BaseIntrinsicLib.lib
UDKLIBS		+= $(UDKLIB)/OpenSslLib.lib $(UDKLIB)/BaseCryptLib.lib $(UDKLIB)/UefiLib.lib $(UDKLIB)/BaseLib.lib $(UDKLIB)/BaseMemoryLib.lib $(UDKLIB)/BasePrintLib.lib
UDKLIBS		+= $(UDKLIB)/UefiMemoryAllocationLib.lib $(UDKLIB)/UefiDevicePathLib.lib $(UDKLIB)/UefiBootServicesTableLib.lib $(UDKLIB)/UefiRuntimeServicesTableLib.lib
UDKLIBS		+= $(UDKLIB)/BaseDebugLibNull.lib
UDKLIBS		+= --end-group

CFLAGS		= -Os -fno-stack-protector -fno-strict-aliasing \
		  -fshort-wchar -Wall -Wsign-compare -Werror -fno-builtin \
		  -Werror=sign-compare -Wno-array-bounds -ffunction-sections -fdata-sections \
		  -fno-asynchronous-unwind-tables -Wno-address -Wno-unused-but-set-variable

# UDK related flags
CFLAGS		+= -DNO_BUILTIN_VA_FUNCS "-DEFIAPI=__attribute__((ms_abi))" -mcmodel=large $(UDKINC)

# ARCH related Flags
CFLAGS		+= -mno-mmx -mno-sse -mno-red-zone -nostdinc -maccumulate-outgoing-args -m64

# custom Flags
CFLAGS		+= -I../sharedInclude

CXXFLAGS	:= $(CFLAGS) -fno-rtti -fno-exceptions

LDFLAGS		= -s -nostdlib -n -q --gc-sections -melf_x86_64 --oformat=elf64-x86-64
LDFLAGS		+= -z common-page-size=0x40 --script=GccBase.lds --defsym=PECOFF_HEADER_SIZE=0x228
LDFLAGS		+= --entry UefiMain -u UefiMain

VERSION		= 0.8

TARGET	= bootX64.efi
OBJS	= loader.o AutoGen.o
SOURCES	= loader.cpp AutoGen.c ../sharedInclude/ct_shim.h

all: $(TARGET)

bootX64.so: $(OBJS) ../shimlib/shimlib.a
	$(LD) -o $@ $(LDFLAGS) -Map $(basename $@).map $^ $(UDKLIBS)

../shimlib/shimlib.a:
	$(MAKE) -C ../shimlib

%.efi: %.so
	./GenFw -e UEFI_APPLICATION -o $@.tmp $^
	./GenFw -v -z -r $@.tmp
	./GenFw -v -s NOW -o $@ $@.tmp

clean:
	$(MAKE) -C ../shimlib clean
	rm -rf $(TARGET) $(OBJS)
	rm -f *.so *.efi *.tar.* *.map *.efi.tmp

GITTAG = $(VERSION)

test-archive:
	@rm -rf /tmp/shim-$(VERSION) /tmp/shim-$(VERSION)-tmp
	@mkdir -p /tmp/shim-$(VERSION)-tmp
	@git archive --format=tar $(shell git branch | awk '/^*/ { print $$2 }') | ( cd /tmp/shim-$(VERSION)-tmp/ ; tar x )
	@git diff | ( cd /tmp/shim-$(VERSION)-tmp/ ; patch -s -p1 -b -z .gitdiff )
	@mv /tmp/shim-$(VERSION)-tmp/ /tmp/shim-$(VERSION)/
	@git log -1 --pretty=format:%H > /tmp/shim-$(VERSION)/commit
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/shim-$(VERSION).tar.bz2 shim-$(VERSION)
	@rm -rf /tmp/shim-$(VERSION)
	@echo "The archive is in shim-$(VERSION).tar.bz2"

tag:
	git tag --sign $(GITTAG) refs/heads/master

archive: tag
	@rm -rf /tmp/shim-$(VERSION) /tmp/shim-$(VERSION)-tmp
	@mkdir -p /tmp/shim-$(VERSION)-tmp
	@git archive --format=tar $(GITTAG) | ( cd /tmp/shim-$(VERSION)-tmp/ ; tar x )
	@mv /tmp/shim-$(VERSION)-tmp/ /tmp/shim-$(VERSION)/
	@git log -1 --pretty=format:%H > /tmp/shim-$(VERSION)/commit
	@dir=$$PWD; cd /tmp; tar -c --bzip2 -f $$dir/shim-$(VERSION).tar.bz2 shim-$(VERSION)
	@rm -rf /tmp/shim-$(VERSION)
	@echo "The archive is in shim-$(VERSION).tar.bz2"
