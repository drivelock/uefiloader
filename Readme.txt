
Setup UDK:
1. Download and extract UDK 2015 from https://github.com/tianocore/tianocore.github.io/wiki/UDK2015

2. Extract the contained UDK2015.MyWorkSpace.zip to your favorite location (beware that Network Folders don't seem to work).

3. (Optional) rename the extracted folder (MyWorkSpace) to "UDK2015". Our Makefiles assume it to be there, but it's changable.

4.  Follow the UDK Documentation "UDK2015-ReleaseNotes-MyWorkSpace.txt" (extracted at 1.) to setup (do not build yet) the UDK.
4a. This Documentations also refers to online docs (e.g. https://github.com/tianocore/tianocore.github.io/wiki/Using-EDK-II-with-Native-GCC#Ubuntu_1604_LTS__Ubuntu_1610).
4b. Be sure to patch OpenSSL as described with http://www.openssl.org/source/openssl-1.0.2d.tar.gz
4c. Versions of UDK required packages we installed:
    build-essential:    12.1ubuntu2
    uuid-dev:           2.27.1-6ubuntu3.4
    iasl:               20160108-2
    git:                1:2.7.4-0ubuntu1.4
    gcc-5:              5.4.0-6ubuntu1~16.04.10
    nasm:               2.11.08-1ubuntu0.1

5. After initializing the build environment ". edksetup.sh BaseTools" and before starting the build you have to modify "Conf/target.txt":
	(see 5b.):	ACTIVE_PLATFORM =
    TARGET = RELEASE
	TARGET_ARCH = X64
	TOOL_CHAIN_TAG = GCC49
5b. choose to either set ACTIVE_PLATFORM to nothing and start build from each of the following folders/packages (e.g. "cd MdePkg" & "build")
    or set ACTIVE_PLATFORM to these packages one by one and start build for each from main folder
    (e.g. in target.txt: "ACTIVE_PLATFORM = MdePkg/MdePkg.dsc" & "build")
5c. Build follwoing packages ("build" will be sufficient no need for the "-t GCC49" option)
    MdePkg/MdePkg.dsc
    CryptoPkg/CryptoPkg.dsc

Build UefiBootLoader:
1. Extract the workspace to your favorite location (this should create the subfolder "UefiBootLoader")
   Preferred: "UDK2015" and "UefiBootLoader" shall reside in the same folder (Makefiles are configured for this)

2. collect used UDK libraries in one folder (manually or by "UefiBootLoader/collectUDKLibs.sh")
   Makefile assumes it to be in the UDK "Build" folder named "Release" (e.g. UDK2015/Build/Release64)

3. If neccessary modify following variables in "UefiBootLoader/loader/Makefile":
    UDK         ?= ../../UDK2015
    (if you installed the UDK elsewhere)

    UDKBIN		:= $(UDKTOOLS)/BinWrappers/PosixLike
    (May need UDK environment. if this don't work, try the alternative)
    alternative :
    UDKBIN		:= $(UDKTOOLS)/Source/C/bin

    UDKLIB		:= $(UDK)/Build/Release64
    (if you copied the UDK libraries elsewhere)

4. build the loader:
    cd UefiBootLoader/loader
    make clean all

Our precomiled version is "UefiBootLoader/bin/bootX64.efi"
