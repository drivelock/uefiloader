// Combined Sgn and DL loader stuff here (and shimlib)

#include <shim.h>
#include <ShimUtil.h>

extern "C"
{
    #include <Protocol/LoadedImage.h>
    #include <Protocol/SimpleFileSystem.h>
    #include <Library/DevicePathLib.h>
    #include <Library/MemoryAllocationLib.h>
    #include <Library/BaseLib.h>

    void setup_console (int);
    void console_error(CHAR16 *, EFI_STATUS);
}


#define DEFAULT_APP L"Auth.efi"
#include "ct_shim.h"


/**
  * @brief Get name of file to be executed with its path
  *
  * @param[in] *li pointer of the loaded image
  * @param[in] &fileName name and path of the file to be executed
  * @return EFI_SUCCESS if file could be read
  */
#define MAXFNSIZE 1024
static EFI_STATUS GetExecutionFile(EFI_LOADED_IMAGE *li, CHAR16 * & fileName)
{
    // private function, no parameter check
// HFE Requests to not load config at current Directory, skip this
//    Indy16String iniFile = GetImagePath(li);
//    iniFile.append(getLoaderConfigName());
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = 0;
    EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    CHAR16 * exeFile = (CHAR16*)AllocateZeroPool(MAXFNSIZE + 1);

    if (exeFile == 0)
        return EFI_OUT_OF_RESOURCES;

    EFI_STATUS status = GetBootServices()->OpenProtocol(li->DeviceHandle, &FsGuid, (VOID **) &FileSystem, GetImageHandle(), 0, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (status == EFI_SUCCESS)
    {
        EFI_FILE *root = 0;
        status = FileSystem->OpenVolume(FileSystem, &root);
        GetBootServices()->CloseProtocol(li->DeviceHandle, &FsGuid, GetImageHandle(), 0);
        if (status == EFI_SUCCESS)
        {
            EFI_FILE_PROTOCOL *File = 0;
            status = root->Open(root, &File, (CHAR16*)getLoaderConfigFullPath(), EFI_FILE_MODE_READ, 0);
            if (status == EFI_SUCCESS)
            {
                UINTN s = MAXFNSIZE;
                status = File->Read(File, &s, exeFile);
                if (exeFile[0] == 0)
                    status = EFI_LOAD_ERROR;

                (void) File->Close(File);
            }
            (void) root->Close(root);
        }
    }

    if (EFI_SUCCESS != status)
    {
/* Fallback if not found, skipped for now by HFE request
        iniFile = getLoaderConfigFullPath();
        status = ReadTextFile(li->DeviceHandle, iniFile, exeFile);
        if (EFI_SUCCESS != status)
*/
            StrCpy(exeFile, (const CHAR16*)DEFAULT_APP);
    }

    // just take the first entry
    for (CHAR16 * chr = exeFile; *chr != 0; ++chr)
    {
        if ((*chr == L';') || (*chr == L'\n') || (*chr == L'\r'))
        {
            *chr = 0;
            break;
        }
    }
    fileName = exeFile;

    return EFI_SUCCESS;
}


extern "C" EFI_STATUS EFIAPI UefiBootServicesTableLibConstructor(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE * SystemTable);
extern "C" EFI_STATUS EFIAPI UefiRuntimeServicesTableLibConstructor(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE * SystemTable);

extern "C" EFI_STATUS EFIAPI UefiLibConstructor(IN EFI_HANDLE ImageHandle, IN EFI_SYSTEM_TABLE * SystemTable);

/**
  * @brief main entry of the executable
  *
  * @param[in] argc number of arguments
  * @param[in] *argv[] filename to be executed (only available in debug version)
  * @return EFI_SUCCESS if suceeded
  */
extern "C" EFI_STATUS EFIAPI UefiMain(EFI_HANDLE ImageHandle, EFI_SYSTEM_TABLE *SystemTable)
{
    EFI_STATUS  executableResult = EFI_NOT_STARTED;


    EFI_STATUS
                status = UefiBootServicesTableLibConstructor(ImageHandle, SystemTable);

    if (EFI_SUCCESS == status)
        status = UefiRuntimeServicesTableLibConstructor(ImageHandle, SystemTable);

    if (EFI_SUCCESS == status)
        status = UefiLibConstructor(GetImageHandle(), GetSystemTable());

    if (status != EFI_SUCCESS)
    {
		GetBootServices()->SetWatchdogTimer(0x001e, 0x0000, 0x0000, NULL); // restart after 30sec
		setup_console(1);
		console_error((CHAR16*)L"Failed to init Lib.", status);

		GetRuntimeServices()->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

        return status;
    }

    // retrieve deviceHandle
    EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
    EFI_LOADED_IMAGE *li = 0;
    status = GetBootServices()->HandleProtocol(GetImageHandle(), &loaded_image_protocol, reinterpret_cast<void**>(&li));

    if ( (status != EFI_SUCCESS) || (0 == li) )
    {
		GetBootServices()->SetWatchdogTimer(0x001e, 0x0000, 0x0000, NULL); // restart after 30sec
		setup_console(1);
		console_error((CHAR16*)L"Failed to get LoadedImageProtocol.", status);
        if (status == EFI_SUCCESS)
            status = EFI_NOT_FOUND;
    }
    else
    {
        EFI_HANDLE volumeDeviceHandle = li->DeviceHandle;

        // read filename from config
        CHAR16 * fileName = 0;
        status = GetExecutionFile(li, fileName);
        if (EFI_SUCCESS == status && fileName && fileName[0] != 0)
        {
            char fileNamecstr[MAXFNSIZE/2 + 1];
            char * cchr = fileNamecstr;
            for (CHAR16 * chr = fileName; *chr != 0; ++chr)
            {
                *cchr++ = (char) *chr;
            }
            *cchr = 0;
            status = ExecuteFile(volumeDeviceHandle, fileName, &executableResult, fileNamecstr);
        }
        else
        {
            // GetExecutionFile can only fail with 0 filename from cfg
            status = EFI_NOT_FOUND;
        }

    }


    if (EFI_ERROR(status))
    {
		GetRuntimeServices()->ResetSystem(EfiResetShutdown, EFI_SUCCESS, 0, NULL);

        return status;
    }

    return executableResult;
}
