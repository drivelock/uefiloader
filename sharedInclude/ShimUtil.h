#ifndef __SHIMUTIL_H_INCLUDED__
#define __SHIMUTIL_H_INCLUDED__


#ifdef __cplusplus
extern "C" {
#endif
#include <Uefi.h>

CHAR16 * EFIAPI UefiDevicePathToStr(IN EFI_DEVICE_PATH_PROTOCOL *devPath);
EFI_DEVICE_PATH * EFIAPI UefiStrToDevicePath(CHAR16* pathName);

const CHAR16 * getDefaultPath();
const CHAR16 * getLoaderBinaryName();
const CHAR16 * getLoaderBinaryFullPath();
const CHAR16 * getLoaderConfigName();
const CHAR16 * getLoaderConfigFullPath();

#ifdef __cplusplus
}
#endif

#endif // !defined __SHIMUTIL_H_INCLUDED__