#ifndef __SHIMI_H_INCLUDED__
#define __SHIMI_H_INCLUDED__


extern "C"
{
    #include <Uefi.h>
    #include <Library/BaseCryptLib.h>
    #include <Library/MemoryAllocationLib.h>
    #include <Guid/FileInfo.h>
    #include <Protocol/LoadedImage.h>
    #include <Protocol/SimpleFileSystem.h>
    #include <Library/BaseMemoryLib.h>
    #include <Guid/ImageAuthentication.h>
    #include <Library/CacheMaintenanceLib.h>
    #include <IndustryStandard/PeImage.h>
    #include <Library/PeCoffLib.h>
    #include <Library/DevicePathLib.h>

    typedef struct {
        WIN_CERTIFICATE Hdr;
        UINT8           CertData[1];
    } WIN_CERTIFICATE_EFI_PKCS;

}

#endif // !defined __SHIMI_H_INCLUDED__