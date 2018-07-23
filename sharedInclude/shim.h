/** @file **********************************************************************
 *
 * \brief SafeGuard Enterprise Boot loader lib
 *
 * $HeadURL: https://pinky.centertools.net/svn/UefiBootLoader/trunk/sw/shim/shim.h $
 * $Rev: 202 $
 * $Author: hfe $
 * $Date: 2013-05-23 15:03:01 +0200 (Do, 23 Mai 2013) $
 *
 * <b>Copyright (c) 1996 - 2013 Utimaco Safeware AG - a member of the Sophos Group</b>
 *
 ******************************************************************************/



#ifndef __SHIM_H_INCLUDED__
#define __SHIM_H_INCLUDED__




extern "C" {
#include <Uefi.h>
#include <Library/UefiRuntimeServicesTableLib.h>
#include <Library/UefiBootServicesTableLib.h>
}
#define GetBootServices()       gBS
#define GetRuntimeServices()    gRT
#define GetImageHandle()        gImageHandle
#define GetSystemTable()        gST
#undef NULL
#define NULL 0

extern
#ifdef __cplusplus
 "C"
#endif
const CHAR16 * UefiErrorCompanyProductName; // used to print the red error boxes

#include "ShimUtil.h"

#ifdef __cplusplus
extern "C" {
#endif
/** \brief This method checks the signature and executes the file handled over
 **
 ** \param[in] volumeDeviceHandle    a valid EFI device Handle from were the file should be loaded
 ** \param[in] fileName              file name of file to be laoded
 ** \param[out] executableResult     return value of the called executeable
 ** \param[in] (OPTIONAL) VerifyModuleId check the provided String with the Data in .ModId Section of the file. If not equal, dont load the file
 **
 ** \retval EFI_SUCCESS             the file was successfully executed, the returnvalue from the file is stored in executableResult
 ** \retval EFI_NOT_FOUND           the file to execute was not found (includes errors regarding the volumeDeviceHande)
 ** \retval EFI_SECURITY_VIOLATION  the file to execute is not properly signed or is blacklisted and therefore wasn't executed
 ** \retval EFI_INVALID_PARAMETER   one of the parameters wasn't set (no optionals allowed)
 ** \retval EFI_xxxxx               any unspecific EFI Error from firmware.
*/
EFI_STATUS EFIAPI ExecuteFile(EFI_HANDLE volumeDeviceHandle, const CHAR16 *fileName, EFI_STATUS *executableResult, const char * VerifyModuleId);

#ifdef __cplusplus
}
#endif

#endif // !defined __SHIM_H_INCLUDED__