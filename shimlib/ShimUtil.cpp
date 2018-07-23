#include "ShimUtil.h"

#include <Protocol/DevicePathFromText.h>
#include <Protocol/DevicePathToText.h>

#include "shim.h"

extern "C"
{

CHAR16 *UefiDevicePathToStr(IN EFI_DEVICE_PATH_PROTOCOL *devPath)
{
    CHAR16 *devicePathText = 0;
    EFI_STATUS Status;
    EFI_DEVICE_PATH_TO_TEXT_PROTOCOL *EfiDevicePathToTextProtocol = 0;
    EFI_GUID EfiDevicePathToTextProtocolGuid = EFI_DEVICE_PATH_TO_TEXT_PROTOCOL_GUID;

    if (devPath == 0)
    {
        return 0;
    }

    Status = GetBootServices()->LocateProtocol(&EfiDevicePathToTextProtocolGuid, 0, (VOID **) &EfiDevicePathToTextProtocol);
    if (EFI_ERROR(Status))
    {
        return 0;
    }

    devicePathText = EfiDevicePathToTextProtocol->ConvertDevicePathToText(devPath, TRUE, TRUE);
    if (devicePathText == 0)
    {
        return 0;
    }

    return devicePathText;
}


EFI_DEVICE_PATH *UefiStrToDevicePath(CHAR16 *pathName)
{
    EFI_DEVICE_PATH *devpath;

    EFI_STATUS Status;
    EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL *EfiDevicePathFromTextProtocol = 0;
    EFI_GUID EfiDevicePathFromTextProtocolGuid = EFI_DEVICE_PATH_FROM_TEXT_PROTOCOL_GUID;

    if (pathName == 0)
    {
        return 0;
    }

    Status = GetBootServices()->LocateProtocol(&EfiDevicePathFromTextProtocolGuid, 0, (VOID **) &EfiDevicePathFromTextProtocol);
    if (EFI_ERROR(Status))
    {
        return 0;
    }

    devpath = EfiDevicePathFromTextProtocol->ConvertTextToDevicePath(pathName);
    if (devpath == 0)
    {
        return 0;
    }

    return devpath;
}



const CHAR16 * getDefaultPath()
{
    return (const CHAR16 *) L"\\EFI\\CenterTools\\Boot\\";
}



const CHAR16 * getLoaderBinaryName()
{
#if defined(__x86_64__)
    return (const CHAR16 *) L"bootX64.efi";
#else
    return (const CHAR16 *) L"boot.efi";
#endif
}



const CHAR16 * getLoaderBinaryFullPath()
{
    return (const CHAR16 *) L"\\EFI\\CenterTools\\Boot\\bootX64.efi";
}



const CHAR16 * getLoaderConfigName()
{
    // just one Cfg file, no speacial for 32 bit
    return (const CHAR16 *) L"bootx64.cfg";
}



const CHAR16 * getLoaderConfigFullPath()
{
    return (const CHAR16 *) L"\\EFI\\CenterTools\\Boot\\bootx64.cfg";
}

} // extern "C"