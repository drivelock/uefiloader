CC		= $(CROSS_COMPILE)gcc
LD		= $(CROSS_COMPILE)ld
OBJCOPY		= $(CROSS_COMPILE)objcopy

ARCH		= x86_64

UDK		?= /media/psf/Projects/linux/UDK2015/Build/Include
UDKINC		:= -I$(UDK)/MdePkg/Include -I$(UDK)/MdeModulePkg/Include -I$(UDK)/IntelFrameworkPkg/Include -I$(UDK)/IntelFrameworkModulePkg/Include -I$(UDK)/CryptoPkg/Include -I$(UDK)/MdePkg/Include/X64

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

CXXFLAGS	= $(CFLAGS) -fno-rtti -fno-exceptions


TARGET	= shimlib.a
OBJS	= shim.o ShimUtil.o console.o guid.o
SOURCES	= shim.cpp ShimUtil.cpp console.c guid.c shimi.h shim_cert.h shim_cert_DL.h console.h guid.h ../sharedInclude/shim.h ../sharedInclude/ShimUtil.h

all: $(TARGET)

shimlib.a: $(OBJS)
	ar rcs shimlib.a $(OBJS)

clean:
	rm -f $(TARGET) $(OBJS)
