#ifndef __CT_SHIM_H_INCLUDED__
#define __CT_SHIM_H_INCLUDED__

#ifdef __cplusplus
extern "C" {
#endif
    #include <Uefi.h>

    const CHAR16 * UefiErrorCompanyProductName = (const CHAR16 *)L"DriveLock SE - DriveLock Pre-Boot Authentication";

#ifdef __cplusplus
}
#endif

#endif // !defined __CT_SHIM_H_INCLUDED__