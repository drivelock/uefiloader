#!/bin/bash

if [ $# -gt 2 ] ; then
    echo "Usage: $0 <path to UDK (default: ../UDK2015)> <path to Target (default: <path to UDK>/Build/Release64)>"
    exit 1
fi

if [ $# -ge 1 ] ; then
    udk=$1
else
    udk=../UDK2015
fi

if [ $# -eq 2 ] ; then
    target=$2
else
    target=$udk/Build/Release64
fi

udk=$udk/Build

mkdir $target

cp $udk/CryptoPkg/RELEASE_GCC49/X64/CryptoPkg/Library/BaseCryptLib/BaseCryptLib/OUTPUT/BaseCryptLib.lib $target
cp $udk/CryptoPkg/RELEASE_GCC49/X64/CryptoPkg/Library/OpensslLib/OpensslLib/OUTPUT/OpensslLib.lib $target
cp $udk/CryptoPkg/RELEASE_GCC49/X64/CryptoPkg/Library/IntrinsicLib/IntrinsicLib/OUTPUT/BaseIntrinsicLib.lib $target

cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BaseCacheMaintenanceLib/BaseCacheMaintenanceLib/OUTPUT/BaseCacheMaintenanceLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BaseDebugLibNull/BaseDebugLibNull/OUTPUT/BaseDebugLibNull.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BaseLib/BaseLib/OUTPUT/BaseLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BaseMemoryLib/BaseMemoryLib/OUTPUT/BaseMemoryLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BasePeCoffExtraActionLibNull/BasePeCoffExtraActionLibNull/OUTPUT/PeCoffExtraActionLibNull.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BasePeCoffLib/BasePeCoffLib/OUTPUT/BasePeCoffLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/BasePrintLib/BasePrintLib/OUTPUT/BasePrintLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/UefiBootServicesTableLib/UefiBootServicesTableLib/OUTPUT/UefiBootServicesTableLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/UefiDevicePathLib/UefiDevicePathLib/OUTPUT/UefiDevicePathLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/UefiLib/UefiLib/OUTPUT/UefiLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/UefiMemoryAllocationLib/UefiMemoryAllocationLib/OUTPUT/UefiMemoryAllocationLib.lib $target
cp $udk/Mde/RELEASE_GCC49/X64/MdePkg/Library/UefiRuntimeServicesTableLib/UefiRuntimeServicesTableLib/OUTPUT/UefiRuntimeServicesTableLib.lib $target
