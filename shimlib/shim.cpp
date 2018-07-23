/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright 2012 Red Hat, Inc <mjg@redhat.com>
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the
 * distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
 * COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Significant portions of this code are derived from Tianocore
 * (http://tianocore.sf.net) and are Copyright 2009-2012 Intel
 * Corporation.
 */

#include "shimi.h"

#include "shim_cert.h"
#include "shim_cert_DL.h"
#include "ShimUtil.h"
extern "C" {
    #include <Library/UefiLib.h>
}
#define PrefixL(x)      L ## x
#define FUNCTION(name)     const wchar_t * FunctionNameString = PrefixL(#name)
#define SGMErrorres(l, c, m)    Print((const CHAR16*)L"%s:%d 0x%x %s\n", FunctionNameString, __LINE__, c, m)
#define SGMError(x)             SGMErrorres x

extern "C"
{
#ifndef NoConsole
    #include "console.h"
#endif
    #include "guid.h"
}


const UINT64 MaxFileSize = 128 * 1024 * 1024;   // 128 MB

#include "shim.h"

typedef enum {
	DATA_FOUND,
	DATA_NOT_FOUND,
	VAR_NOT_FOUND
} CHECK_STATUS;

// moved needed functions from lib/variables.c here
static EFI_STATUS
get_variable_attr(CHAR16 *var, UINT8 **data, UINTN *len, EFI_GUID owner,
		  UINT32 *attributes)
{
	EFI_STATUS efi_status;

	*len = 0;

	efi_status = GetRuntimeServices()->GetVariable(var, &owner,
				       NULL, len, NULL);
	if (efi_status != EFI_BUFFER_TOO_SMALL)
		return efi_status;

	*data = (UINT8*)AllocateZeroPool(*len);
	if (!*data)
		return EFI_OUT_OF_RESOURCES;

	efi_status = GetRuntimeServices()->GetVariable(var, &owner,
				       attributes, len, *data);

	if (efi_status != EFI_SUCCESS) {
		FreePool(*data);
		*data = NULL;
	}
	return efi_status;
}

static EFI_STATUS
get_variable(CHAR16 *var, UINT8 **data, UINTN *len, EFI_GUID owner)
{
	return get_variable_attr(var, data, len, owner, NULL);
}


static EFI_STATUS ConnectAllHandles()
{
    UINTN HandleCount = 0;
    EFI_HANDLE *HandleBuffer = 0;
    UINTN Index;
    EFI_STATUS Status = GetBootServices()->LocateHandleBuffer(AllHandles, 0, 0, &HandleCount, &HandleBuffer);
    if (EFI_ERROR (Status))
    {
        return Status;
    }

    for (Index = 0; Index < HandleCount; Index++)
    {
        (void) GetBootServices()->ConnectController(HandleBuffer[Index], 0, 0, TRUE);   // Ignore errors and continue to connect
    }

    if (HandleBuffer != NULL)
    {
        GetBootServices()->FreePool(HandleBuffer);
    }

    return EFI_SUCCESS;
}


static void *ImageAddress (void *image, UINT64 size, UINT64 address)
{
	if (address >= size)
		return NULL;

	return ((char*)image) + address;
}


static int
image_is_64_bit(EFI_IMAGE_OPTIONAL_HEADER_UNION *PEHdr)
{
	// .Magic is the same offset in all cases
	if (PEHdr->Pe32Plus.OptionalHeader.Magic
			== EFI_IMAGE_NT_OPTIONAL_HDR64_MAGIC)
		return 1;
	return 0;
}



static const UINT16 machine_type =
#if defined(__x86_64__)
	IMAGE_FILE_MACHINE_X64;
#elif defined(__aarch64__)
	IMAGE_FILE_MACHINE_ARM64;
#elif defined(__arm__)
	IMAGE_FILE_MACHINE_ARMTHUMB_MIXED;
#elif defined(__i386__) || defined(__i486__) || defined(__i686__)
	IMAGE_FILE_MACHINE_I386;
#elif defined(__ia64__)
	IMAGE_FILE_MACHINE_IA64;
#else
#error this architecture is not supported by shim
#endif



static BOOLEAN verify_x509(UINT8 *Cert, UINTN CertSize)
{
	UINTN length;

	if (!Cert || CertSize < 4)
		return FALSE;

	/*
	 * A DER encoding x509 certificate starts with SEQUENCE(0x30),
	 * the number of length bytes, and the number of value bytes.
	 * The size of a x509 certificate is usually between 127 bytes
	 * and 64KB. For convenience, assume the number of value bytes
	 * is 2, i.e. the second byte is 0x82.
	 */
	if (Cert[0] != 0x30 || Cert[1] != 0x82)
		return FALSE;

	length = Cert[2]<<8 | Cert[3];
	if (length != (CertSize - 4))
		return FALSE;

	return TRUE;
}

static CHECK_STATUS check_db_cert_in_ram(EFI_SIGNATURE_LIST *CertList,
					 UINTN dbsize,
					 WIN_CERTIFICATE_EFI_PKCS *data,
					 UINT8 *hash)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertSize;
	BOOLEAN IsFound = FALSE;
	EFI_GUID CertType = X509_GUID;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		if (CompareGuid (&CertList->SignatureType, &CertType) == 0) {
			Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
			CertSize = CertList->SignatureSize - sizeof(EFI_GUID);
			if (verify_x509(Cert->SignatureData, CertSize)) {
				IsFound = AuthenticodeVerify (data->CertData,
							      data->Hdr.dwLength - sizeof(data->Hdr),
							      Cert->SignatureData,
							      CertSize,
							      hash, SHA256_DIGEST_SIZE);
				if (IsFound)
					return DATA_FOUND;
			}
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	return DATA_NOT_FOUND;
}

static CHECK_STATUS check_db_cert(CHAR16 *dbname, EFI_GUID guid,
				  WIN_CERTIFICATE_EFI_PKCS *data, UINT8 *hash)
{
	CHECK_STATUS rc;
	EFI_STATUS efi_status;
	EFI_SIGNATURE_LIST *CertList;
	UINTN dbsize = 0;
	UINT8 *db;

	efi_status = get_variable(dbname, &db, &dbsize, guid);

	if (efi_status != EFI_SUCCESS)
		return VAR_NOT_FOUND;

	CertList = (EFI_SIGNATURE_LIST *)db;

	rc = check_db_cert_in_ram(CertList, dbsize, data, hash);

	FreePool(db);

	return rc;
}

/*
 * Check a hash against an EFI_SIGNATURE_LIST in a buffer
 */
static CHECK_STATUS check_db_hash_in_ram(EFI_SIGNATURE_LIST *CertList,
					 UINTN dbsize, UINT8 *data,
					 int SignatureSize, EFI_GUID CertType)
{
	EFI_SIGNATURE_DATA *Cert;
	UINTN CertCount, Index;
	BOOLEAN IsFound = FALSE;

	while ((dbsize > 0) && (dbsize >= CertList->SignatureListSize)) {
		CertCount = (CertList->SignatureListSize -sizeof (EFI_SIGNATURE_LIST) - CertList->SignatureHeaderSize) / CertList->SignatureSize;
		Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) CertList + sizeof (EFI_SIGNATURE_LIST) + CertList->SignatureHeaderSize);
		if (CompareGuid(&CertList->SignatureType, &CertType) == 0) {
			for (Index = 0; Index < CertCount; Index++) {
				if (CompareMem (Cert->SignatureData, data, SignatureSize) == 0) {
					//
					// Find the signature in database.
					//
					IsFound = TRUE;
					break;
				}

				Cert = (EFI_SIGNATURE_DATA *) ((UINT8 *) Cert + CertList->SignatureSize);
			}
			if (IsFound) {
				break;
			}
		}

		dbsize -= CertList->SignatureListSize;
		CertList = (EFI_SIGNATURE_LIST *) ((UINT8 *) CertList + CertList->SignatureListSize);
	}

	if (IsFound)
		return DATA_FOUND;

	return DATA_NOT_FOUND;
}

/*
 * Check a hash against an EFI_SIGNATURE_LIST in a UEFI variable
 */
static CHECK_STATUS check_db_hash(CHAR16 *dbname, EFI_GUID guid, UINT8 *data,
				  int SignatureSize, EFI_GUID CertType)
{
	EFI_STATUS efi_status;
	EFI_SIGNATURE_LIST *CertList;
	UINTN dbsize = 0;
	UINT8 *db;

	efi_status = get_variable(dbname, &db, &dbsize, guid);

	if (efi_status != EFI_SUCCESS) {
		return VAR_NOT_FOUND;
	}

	CertList = (EFI_SIGNATURE_LIST *)db;

	CHECK_STATUS rc = check_db_hash_in_ram(CertList, dbsize, data,
						SignatureSize, CertType);
	FreePool(db);
	return rc;

}

/*
 * Check whether the binary signature or hash are present in dbx or the
 * built-in blacklist
 */
static EFI_STATUS check_blacklist (WIN_CERTIFICATE_EFI_PKCS *cert,
				   UINT8 *sha256hash, UINT8 *sha1hash)
{
	EFI_GUID secure_var = EFI_IMAGE_SECURITY_DATABASE_GUID;
	if (check_db_hash((CHAR16*)L"dbx", secure_var, sha256hash, SHA256_DIGEST_SIZE,
			  SHA256_GUID) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (check_db_hash((CHAR16*)L"dbx", secure_var, sha1hash, SHA1_DIGEST_SIZE,
			  SHA1_GUID) == DATA_FOUND)
		return EFI_ACCESS_DENIED;
	if (cert && check_db_cert((CHAR16*)L"dbx", secure_var, cert, sha256hash) ==
				DATA_FOUND)
		return EFI_ACCESS_DENIED;

	return EFI_SUCCESS;
}

#define check_size_line(data, datasize_in, hashbase, hashsize, l) {	\
	if ((UINTN)hashbase >					\
			(UINTN)data + datasize_in) {		\
        SGMError((SGMT_MAJOR, (unsigned long)-1, L"Invalid hash base")); \
		goto done;						\
	}								\
	if ((UINTN)hashbase + hashsize >			\
			(UINTN)data + datasize_in) {		\
        SGMError((SGMT_MAJOR, (unsigned long)-1, L"Invalid hash size")); \
		goto done;						\
	}								\
}
#define check_size(d,ds,h,hs) check_size_line(d,ds,h,hs,__LINE__)

/*
 * Calculate the SHA1 and SHA256 hashes of a binary
 */

static EFI_STATUS generate_hash (UINT8 *data, unsigned int datasize_in,
				 UINT8 *sha256hash, UINT8 *sha1hash, const char * VerifyModuleId)
{
    FUNCTION(generate_hash);
	UINTN sha256ctxsize, sha1ctxsize;
	unsigned int size = datasize_in;
	void *sha256ctx = NULL, *sha1ctx = NULL;
	UINT8 *hashbase;
	UINTN hashsize;
	unsigned int SumOfBytesHashed, SumOfSectionBytes;
	unsigned int index, pos;
	unsigned int datasize;
	EFI_IMAGE_SECTION_HEADER  *Section;
	EFI_IMAGE_SECTION_HEADER  *SectionHeader = NULL;
	EFI_STATUS status = EFI_SUCCESS;
	EFI_IMAGE_DOS_HEADER *DosHdr = (EFI_IMAGE_DOS_HEADER *) data;
	unsigned int PEHdr_offset = 0;
    EFI_IMAGE_OPTIONAL_HEADER_UNION *hdr;
    EFI_IMAGE_DATA_DIRECTORY *SecDir;
    bool IdChecked = false;
    EFI_IMAGE_DATA_DIRECTORY *dd = 0;

    // Check Headers Manually (again), because we need it inplace and not as a copy to calc addresses and sizes

    // at least this size should be there, even if the Dos Header is missing and it starts with the PE Header
	if (datasize_in < sizeof(EFI_IMAGE_DOS_HEADER)) {
        SGMError((SGMT_MAJOR, (unsigned long)-1, L"Invalid data size"));
		return EFI_INVALID_PARAMETER;
	}
	size = datasize = (unsigned int)datasize_in;

    // if no DOSHeader, it starts with PE header
	if (DosHdr->e_magic == EFI_IMAGE_DOS_SIGNATURE) {
    	PEHdr_offset = DosHdr->e_lfanew;
	}

    hdr = (EFI_IMAGE_OPTIONAL_HEADER_UNION*) ImageAddress(data, datasize, PEHdr_offset);

    // it looks like all used optionalheader fields are the same in Pe32 & Pe32Plus... we hope !
    // set first hash range here to do a sizecheck to safely access PE Header
	// Hash start to checksum
	hashbase = data;
	hashsize = (UINT8 *)&hdr->Pe32.OptionalHeader.CheckSum -
		hashbase;
	check_size(data, datasize_in, hashbase, hashsize);

    // Check PE Header
    if (hdr->Pe32.Signature != EFI_IMAGE_NT_SIGNATURE)
    {
        SGMError((SGMT_MAJOR, (unsigned long)-1, L"Invalid signature"));
		return EFI_INVALID_PARAMETER;
    }

    SecDir = image_is_64_bit(hdr) ? &hdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] :
                                    &hdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	sha256ctxsize = Sha256GetContextSize();
	sha256ctx = AllocatePool(sha256ctxsize);

	sha1ctxsize = Sha1GetContextSize();
	sha1ctx = AllocatePool(sha1ctxsize);

	if (!sha256ctx || !sha1ctx) {
        SGMError((SGMT_MAJOR, (unsigned long)-1, L"Unable to allocate memory for hash context"));
		return EFI_OUT_OF_RESOURCES;
	}

	if (!Sha256Init(sha256ctx) || !Sha1Init(sha1ctx)) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to initialise hash"));
		goto done;
	}

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to generate hash"));
		goto done;
	}

	/* Hash post-checksum to start of certificate table */
	hashbase = (UINT8 *)&hdr->Pe32.OptionalHeader.CheckSum +
		sizeof (UINT32);
	hashsize = (UINT8 *)SecDir - hashbase;
	check_size(data, datasize_in, hashbase, hashsize);

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to generate hash"));
		goto done;
	}

	/* Hash end of certificate table to end of image header */
	dd = SecDir + 1;
	hashbase = (UINT8 *)dd;
	hashsize = hdr->Pe32.OptionalHeader.SizeOfHeaders - (unsigned long)((UINT8 *)dd - data);
	if (hashsize > datasize_in) {
		status = EFI_INVALID_PARAMETER;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Data Directory size is invalid"));
		goto done;
	}
	check_size(data, datasize_in, hashbase, hashsize);

	if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
	    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to generate hash"));
		goto done;
	}

	/* Sort sections */
	SumOfBytesHashed = hdr->Pe32.OptionalHeader.SizeOfHeaders;

	/* Validate section locations and sizes */
	for (index = 0, SumOfSectionBytes = 0; index < hdr->Pe32.FileHeader.NumberOfSections; index++) {
		EFI_IMAGE_SECTION_HEADER  *SectionPtr;

		/* Validate SectionPtr is within image */
		SectionPtr = (EFI_IMAGE_SECTION_HEADER*) ImageAddress(data, datasize,
			PEHdr_offset +
			sizeof (UINT32) +
			sizeof (EFI_IMAGE_FILE_HEADER) +
			hdr->Pe32.FileHeader.SizeOfOptionalHeader +
			(index * sizeof(*SectionPtr)));
		if (!SectionPtr) {
			status = EFI_INVALID_PARAMETER;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Malformed section"));
			goto done;
		}
		/* Validate section size is within image. */
		if (SectionPtr->SizeOfRawData >
		    datasize - SumOfBytesHashed - SumOfSectionBytes) {
			status = EFI_INVALID_PARAMETER;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Malformed section size"));
			goto done;
		}
		SumOfSectionBytes += SectionPtr->SizeOfRawData;
	}

	SectionHeader = (EFI_IMAGE_SECTION_HEADER *) AllocateZeroPool (sizeof (EFI_IMAGE_SECTION_HEADER) * hdr->Pe32.FileHeader.NumberOfSections);
	if (SectionHeader == NULL) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to allocate section header"));
		goto done;
	}

	/* Already validated above */
	Section = (EFI_IMAGE_SECTION_HEADER*) ImageAddress(data, datasize,
		PEHdr_offset +
		sizeof (UINT32) +
		sizeof (EFI_IMAGE_FILE_HEADER) +
		hdr->Pe32.FileHeader.SizeOfOptionalHeader);

	/* Sort the section headers */
	for (index = 0; index < hdr->Pe32.FileHeader.NumberOfSections; index++) {
		pos = index;
		while ((pos > 0) && (Section->PointerToRawData < SectionHeader[pos - 1].PointerToRawData)) {
			CopyMem (&SectionHeader[pos], &SectionHeader[pos - 1], sizeof (EFI_IMAGE_SECTION_HEADER));
			pos--;
		}
		CopyMem (&SectionHeader[pos], Section, sizeof (EFI_IMAGE_SECTION_HEADER));
		Section += 1;
	}

    IdChecked = false;

	/* Hash the sections */
	for (index = 0; index < hdr->Pe32.FileHeader.NumberOfSections; index++) {
		Section = &SectionHeader[index];
		if (Section->SizeOfRawData == 0) {
			continue;
		}
		hashbase  = (UINT8*) ImageAddress(data, size, Section->PointerToRawData);

		if (!hashbase) {
			status = EFI_INVALID_PARAMETER;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Malformed section header"));
			goto done;
		}

		/* Verify hashsize within image. */
		if (Section->SizeOfRawData >
		    datasize - Section->PointerToRawData) {
			status = EFI_INVALID_PARAMETER;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Malformed section raw size"));
			goto done;
		}
		hashsize  = (unsigned int) Section->SizeOfRawData;
		check_size(data, datasize_in, hashbase, hashsize);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			status = EFI_OUT_OF_RESOURCES;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to generate hash"));
			goto done;
		}
		SumOfBytesHashed += Section->SizeOfRawData;

        if (VerifyModuleId)
        {
            if (0 == CompareMem(Section->Name, ".ModId", MIN(7, EFI_IMAGE_SIZEOF_SHORT_NAME)))
            {
                UINTN idlen = 0;
                const char * chr = VerifyModuleId;
                while (*chr++ != 0)
                    ++idlen;
                ++idlen;    // check 0 terminator
                if ((idlen > hashsize) || (0 != CompareMem(VerifyModuleId, hashbase, idlen)))
                {
                    status = EFI_SECURITY_VIOLATION;
                    SGMError((SGMT_MAJOR, (unsigned long)status, L"Module Id don't match"));
                    goto done;
                }
                IdChecked = true;
            }
        }
	}

    if (VerifyModuleId && !IdChecked)
    {
        status = EFI_SECURITY_VIOLATION;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Module Id section not found"));
        goto done;
    }

	/* Hash all remaining data */
	if (datasize > SumOfBytesHashed) {
		hashbase = data + SumOfBytesHashed;
		hashsize = datasize - SecDir->Size - SumOfBytesHashed;
		check_size(data, datasize_in, hashbase, hashsize);

		if (!(Sha256Update(sha256ctx, hashbase, hashsize)) ||
		    !(Sha1Update(sha1ctx, hashbase, hashsize))) {
			status = EFI_OUT_OF_RESOURCES;
            SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to generate hash"));
			goto done;
		}
	}

	if (!(Sha256Final(sha256ctx, sha256hash)) ||
	    !(Sha1Final(sha1ctx, sha1hash))) {
		status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Unable to finalise hash"));
		goto done;
	}

done:
	if (SectionHeader)
		FreePool(SectionHeader);
	if (sha1ctx)
		FreePool(sha1ctx);
	if (sha256ctx)
		FreePool(sha256ctx);

	return status;
}

/*
 * Check that the signature is valid and matches the binary
 */
static EFI_STATUS verify_buffer (UINT8 *data, unsigned int datasize,
			 EFI_IMAGE_OPTIONAL_HEADER_UNION *hdr, const char * VerifyModuleId)
{
    FUNCTION(verify_buffer);

	UINT8 sha256hash[SHA256_DIGEST_SIZE];
	UINT8 sha1hash[SHA1_DIGEST_SIZE];
	EFI_STATUS status = EFI_ACCESS_DENIED;
	WIN_CERTIFICATE_EFI_PKCS *cert = NULL;
	unsigned int size = datasize;
    EFI_IMAGE_DATA_DIRECTORY *SecDir = image_is_64_bit(hdr) ?
                                            &hdr->Pe32Plus.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY] :
                                            &hdr->Pe32.OptionalHeader.DataDirectory[EFI_IMAGE_DIRECTORY_ENTRY_SECURITY];

	if (SecDir->Size != 0) {
		cert = (WIN_CERTIFICATE_EFI_PKCS*) ImageAddress (data, size, SecDir->VirtualAddress);

		if (!cert) {
            SGMError((SGMT_MAJOR, (unsigned long)-1, L"Certificate located outside the image"));
			return EFI_INVALID_PARAMETER;
		}

		if (cert->Hdr.wCertificateType !=
		    WIN_CERT_TYPE_PKCS_SIGNED_DATA) {
            SGMError((SGMT_MAJOR, (unsigned long)-1, L"Unsupported certificate type"));
			return EFI_UNSUPPORTED;
		}
	}

	status = generate_hash(data, datasize, sha256hash, sha1hash, VerifyModuleId);

	if (status != EFI_SUCCESS)
		return status;

	/*
	 * Ensure that the binary isn't blacklisted
	 */
	status = check_blacklist(cert, sha256hash, sha1hash);

	if (status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)status, L"Binary is blacklisted."));
#ifndef NoConsole
		setup_console(1);
		console_error((CHAR16*)L"Binary is blacklisted.", status);
#endif
		return status;
	}

	if (cert) {
		/*
		 * Check against the shim build key
		 */
		if (sizeof(shim_cert) &&
		    AuthenticodeVerify(cert->CertData,
			       SecDir->Size - sizeof(cert->Hdr),
			       shim_cert, sizeof(shim_cert), sha256hash,
			       SHA256_DIGEST_SIZE)) {
			status = EFI_SUCCESS;
			return status;
		}

        // not matched, check second cert
		if (sizeof(shim_cert_DL) &&
		    AuthenticodeVerify(cert->CertData,
			       SecDir->Size - sizeof(cert->Hdr),
			       shim_cert_DL, sizeof(shim_cert_DL), sha256hash,
			       SHA256_DIGEST_SIZE)) {
			status = EFI_SUCCESS;
			return status;
		}
	}

	status = EFI_ACCESS_DENIED;

	return status;
}


/*
 * Once the image has been loaded it needs to be validated and relocated
 */
// declare interanal function from PeCoffLib
extern "C" RETURN_STATUS
PeCoffLoaderGetPeHeader (
  IN OUT PE_COFF_LOADER_IMAGE_CONTEXT         *ImageContext,
  OUT    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION  Hdr
  );

static UINTN ImageReadSize = 0;
static RETURN_STATUS EFIAPI ShimImageReadFromMemory(VOID *FileHandle, UINTN FileOffset, UINTN *ReadSize, VOID *Buffer)
{
    if (!FileHandle || !ReadSize || !Buffer)
        return EFI_INVALID_PARAMETER;

    if (FileOffset >= ImageReadSize)
        *ReadSize = 0;
    else if (FileOffset + *ReadSize > ImageReadSize)
        *ReadSize = ImageReadSize - FileOffset;

    if (*ReadSize > 0)
        CopyMem (Buffer, ((UINT8 *)FileHandle) + FileOffset, *ReadSize);

    return RETURN_SUCCESS;
}

static EFI_STATUS handle_module(void *data, unsigned int datasize, EFI_LOADED_IMAGE *li, EFI_IMAGE_ENTRY_POINT * entry_point, const char * VerifyModuleId)
{
    FUNCTION(handle_module);

	EFI_STATUS efi_status;
	PE_COFF_LOADER_IMAGE_CONTEXT context;
    EFI_IMAGE_OPTIONAL_HEADER_UNION     Hdr;
    EFI_IMAGE_OPTIONAL_HEADER_PTR_UNION pHdr;

    // Init contxt with file data
    ZeroMem(&context, sizeof(context));
    context.Handle = data;
    context.ImageRead = ShimImageReadFromMemory;    // replaced PeCoffLoaderImageReadFromMemory because this function does not check datasize
    ImageReadSize = datasize;

	/*
	 * The binary header contains relevant context and section pointers
	 */
    // Need secDir for verify buffers, so read PE header for us.. (done internaly by following PeCoffLoaderGetImageInfo)
    // Also generate_hash needs this + PeHeader, but have to read/check it manually
    // so this may be unnesessary if we rework it to check it manually for both (but once!)
    pHdr.Union = &Hdr;
	efi_status = PeCoffLoaderGetPeHeader(&context, pHdr);
	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to read header"));
		return efi_status;
	}

    efi_status = PeCoffLoaderGetImageInfo(&context);
	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to read header"));
		return efi_status;
	}

    // we only load the same architecture
    if (context.Machine != machine_type) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unsupported architecture"));
		return EFI_UNSUPPORTED;
	}

    if (context.RelocationsStripped || context.IsTeImage)
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unsupported format"));
		return EFI_UNSUPPORTED;
	}

    switch (context.ImageType)
    {
        case EFI_IMAGE_SUBSYSTEM_EFI_APPLICATION:
            context.ImageCodeMemoryType = EfiLoaderCode;
            context.ImageDataMemoryType = EfiLoaderData;
            break;
        case EFI_IMAGE_SUBSYSTEM_EFI_BOOT_SERVICE_DRIVER:
            context.ImageCodeMemoryType = EfiBootServicesCode;
            context.ImageDataMemoryType = EfiBootServicesData;
            break;
        case EFI_IMAGE_SUBSYSTEM_EFI_RUNTIME_DRIVER:
            context.ImageCodeMemoryType = EfiRuntimeServicesCode;
            context.ImageDataMemoryType = EfiRuntimeServicesData;
            break;
        default:
            SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unsupported type"));
            return EFI_UNSUPPORTED;
    }

	/*
	 * We verify the binary
	 */
	efi_status = verify_buffer((UINT8*)data, datasize, pHdr.Union, VerifyModuleId);

	if (EFI_ERROR(efi_status)) {
//Print(L"Verify returned %r\n", efi_status);
			return efi_status;
    }

    efi_status = GetBootServices()->AllocatePages(AllocateAnyPages, (EFI_MEMORY_TYPE) context.ImageCodeMemoryType, (UINTN) EFI_SIZE_TO_PAGES(context.ImageSize), &context.ImageAddress);

	if (EFI_ERROR(efi_status) || !context.ImageAddress) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to allocate image buffer"));
		return EFI_OUT_OF_RESOURCES;
	}

    li->ImageBase = (void*)context.ImageAddress;
    context.ImageAddress = (context.ImageAddress + context.SectionAlignment - 1) & ~((UINTN)context.SectionAlignment - 1);

    // fill remaining loaded image data
    li->ImageCodeType = (EFI_MEMORY_TYPE) context.ImageCodeMemoryType;
    li->ImageDataType = (EFI_MEMORY_TYPE) context.ImageDataMemoryType;
    li->ImageSize = context.ImageSize;
    li->Unload = 0;

    efi_status = PeCoffLoaderLoadImage(&context);
    if (EFI_ERROR(efi_status))
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to load image"));
        GetBootServices()->FreePages((UINT64)li->ImageBase, (UINTN) EFI_SIZE_TO_PAGES(li->ImageSize));
		return efi_status;
    }

    efi_status = PeCoffLoaderRelocateImage(&context);
    if (EFI_ERROR(efi_status))
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to relocate image"));
        GetBootServices()->FreePages((UINT64)li->ImageBase, (UINTN) EFI_SIZE_TO_PAGES(li->ImageSize));
		return efi_status;
    }

    (void) InvalidateInstructionCacheRange((void*)context.ImageAddress, (UINTN) context.ImageSize);

    *entry_point = (EFI_IMAGE_ENTRY_POINT)context.EntryPoint;

	if (!*entry_point) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Invalid entry point"));
        GetBootServices()->FreePages((UINT64)li->ImageBase, (UINTN) EFI_SIZE_TO_PAGES(li->ImageSize));
		return EFI_UNSUPPORTED;
	}

	return EFI_SUCCESS;
}


static inline INTN
//__attribute__((unused))
StrnCaseCmp(CHAR16 *s0, CHAR16 *s1, int n)
{
	CHAR16 c0, c1;
	int x = 0;
	while (n > x++) {
		if (*s0 == L'\0' || *s1 == L'\0')
			return *s1 - *s0;
		c0 = (*s0 >= L'a' && *s0 <= L'z') ? *s0 - 32 : *s0;
		c1 = (*s1 >= L'a' && *s1 <= L'z') ? *s1 - 32 : *s1;
		if (c0 != c1)
			return c1 - c0;
		s0++;
		s1++;
	}
	return 0;
}

// ImagePath can be fully qualified or just filename, returned PathName is fully qualified
static EFI_STATUS generate_path(EFI_DEVICE_PATH *devpath, const CHAR16 *ImagePath,
				CHAR16 **PathName, EFI_HANDLE VolumeDeviceHandle)
{
    FUNCTION(generate_path);
	unsigned int i;
	int j, last = -1;
	unsigned int pathlen = 0;
	EFI_STATUS efi_status = EFI_SUCCESS;
	CHAR16 *bootpath;

	bootpath = UefiDevicePathToStr(devpath);

	pathlen = (unsigned int)StrLen(bootpath);

	/*
	 * DevicePathToStr() concatenates two nodes with '/'.
	 * Convert '/' to '\\'.
	 */
	for (i = 0; i < pathlen; i++) {
		if (bootpath[i] == '/')
			bootpath[i] = '\\';
	}

	for (i=pathlen; i>0; i--) {
		if (bootpath[i] == '\\' && bootpath[i-1] == '\\')
			bootpath[i] = '/';
		else if (last == -1 && bootpath[i] == '\\')
			last = i;
	}

	if (last == -1 && bootpath[0] == '\\')
		last = 0;
	bootpath[last+1] = '\0';

	if (last > 0) {
		for (i = 0, j = 0; bootpath[i] != '\0'; i++) {
			if (bootpath[i] != '/') {
				bootpath[j] = bootpath[i];
				j++;
			}
		}
		bootpath[j] = '\0';
	}

	while (*ImagePath == '\\')
		ImagePath++;

    EFI_FILE *root = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = 0;
    EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;

	*PathName = (CHAR16*) AllocatePool(MAX(StrSize(bootpath), StrSize(getDefaultPath())) + StrSize(ImagePath));

	if (!*PathName) {
		efi_status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to allocate path buffer"));
		goto error;
	}

	*PathName[0] = '\0';
	if (StrnCaseCmp(bootpath, (CHAR16*)ImagePath, (int)StrLen(bootpath)))
		StrCat(*PathName, bootpath);

    StrCat(*PathName, ImagePath);

    // Does file exsit ?
    efi_status = GetBootServices()->OpenProtocol(VolumeDeviceHandle, &FsGuid, (VOID **) &FileSystem, GetImageHandle(), 0, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (efi_status == EFI_SUCCESS)
    {
        efi_status = FileSystem->OpenVolume(FileSystem, &root);
        GetBootServices()->CloseProtocol(VolumeDeviceHandle, &FsGuid, GetImageHandle(), 0);
        if (efi_status == EFI_SUCCESS)
        {
            EFI_FILE_PROTOCOL *File = 0;
            efi_status = root->Open(root, &File, *PathName, EFI_FILE_MODE_READ, 0);
            (void) File->Close(File);
            (void) root->Close(root);
        }
    }

    if (EFI_ERROR(efi_status))
    {
        // Does not exist, use defaultpath
        *PathName[0] = '\0';
        StrCat(*PathName, getDefaultPath());
        StrCat(*PathName, ImagePath);
    }
    efi_status = EFI_SUCCESS;
error:
	GetBootServices()->FreePool(bootpath);

	return efi_status;
}


static EFI_STATUS create_imagehandle(EFI_HANDLE image_handle, EFI_LOADED_IMAGE * org_li, CHAR16 * PathName, EFI_HANDLE * new_handle, EFI_LOADED_IMAGE ** new_li, EFI_LOADED_IMAGE * new_li_bak)
{
    FUNCTION(create_imagehandle);

    EFI_STATUS  efi_status;
#ifdef CREATE_LI_BY_SELF
    *new_li = (EFI_LOADED_IMAGE *) AllocatePool(sizeof(EFI_LOADED_IMAGE));
    if (0 == *new_li)
    {
		efi_status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to allocate LoadedImageProtocol buffer"));
        return efi_status;
	}

    // create Loaded Image struct from our own
    memcpy(*new_li, org_li, sizeof(EFI_LOADED_IMAGE));
    (*new_li)->DeviceHandle = volumeDeviceHandle;
    (*new_li)->Unload = 0;
    (*new_li)->FilePath = 0;
    (*new_li)->LoadOptions = 0;

    // Handle has to be created after loading, so postponed into run_module
#else
	EFI_DEVICE_PATH * FilePath = NULL;

	FilePath = FileDevicePath(org_li->DeviceHandle, (CHAR16*)getLoaderBinaryFullPath());

	// load a new image from disk to get a new valid image handle, do not use a cloned handle like shim loader sample code did.
	// Use our MS signed ct shim loader binary because this file we could load anyway (e.g. Secure boot enabled).
	// Do it to always to get a "clean" image handle.
    // what abount the false data in the private image_handle part ? can we ignore it,
    // because we nerver use the handle to load/unload/start the an image or used as parent image ?
	*new_handle = 0;
    efi_status = GetBootServices()->LoadImage(FALSE,       // Boot policy
                                image_handle, // Parent image handle
                                FilePath,    // Device path
                                NULL,        // Source buffer
                                0,           // Source size
                                new_handle);


    GetBootServices()->FreePool(FilePath);

	if (efi_status != EFI_SUCCESS)
	{
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to load image"));
#ifndef NoConsole
        setup_console(1);
        console_error((CHAR16*)L"Failed to load image", efi_status);
#endif
        return efi_status;
	}

	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;
	efi_status = GetBootServices()->OpenProtocol(*new_handle,
				       &loaded_image_protocol, (void **)new_li, image_handle, 0, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);

	if (efi_status != EFI_SUCCESS)
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to get LoadedImageProtocol"));
#ifndef NoConsole
		setup_console(1);
		console_error((CHAR16*)L"Failed to get LoadedImageProtocol", efi_status);
#endif
		return efi_status;
	}

	/*
	 * We need to modify the loaded image protocol entry before running
	 * the new binary, so make an backup
	 */
	CopyMem(new_li_bak, *new_li, sizeof(EFI_LOADED_IMAGE));
    (*new_li)->LoadOptions = 0; // copy from out image, if any
#endif
    // MBA: just copy the LoadOptions from our original
    // TODO by Component Owner: is this useful ? whats in there ?
    if (0 < (*new_li)->LoadOptionsSize)
    {
        // MBA: if allocte fails we just delete the LoadOptions for the new binary
        // TODO by Component Owner: can it hurt to delete it ? if yes we should abort if alloc fails
        (*new_li)->LoadOptions = AllocatePool((*new_li)->LoadOptionsSize);
        if ((*new_li)->LoadOptions)
            CopyMem((*new_li)->LoadOptions, org_li->LoadOptions, (*new_li)->LoadOptionsSize);
        else
        {
            SGMError((SGMT_MINOR, (unsigned long)efi_status, L"Unable to allocate LoadOptions buffer, ignore"));
            (*new_li)->LoadOptionsSize = 0;
        }
    }

    (*new_li)->FilePath = FileDevicePath(0, PathName);
    // MBA : workaround PROTOTYPE for Dell DevicePath Protocol problem
    // TODO refactor if necessary
    if ( (0 == (*new_li)->FilePath) && (0 != org_li->FilePath) )
    {
        // Failed, create a dummy by coping our path (if any)
        // first count the Length
        EFI_DEVICE_PATH_PROTOCOL *dp = org_li->FilePath;
        UINT16 l = 0;
        // TODO Subtype is not checked now, eventually this has to be also checked
        while (0x7f != (dp->Type & 0x7f))
        {
            l += *reinterpret_cast<UINT16*>(dp->Length);
            dp = reinterpret_cast<EFI_DEVICE_PATH_PROTOCOL*>(reinterpret_cast<UINT8*>(dp) + *reinterpret_cast<UINT16*>(dp->Length));
        }
        // add length of END token
        l += *reinterpret_cast<UINT16*>(dp->Length);

		// now allocate & copy
        (*new_li)->FilePath = (EFI_DEVICE_PATH_PROTOCOL *) AllocatePool(l);
        if (0 != (*new_li)->FilePath)
            CopyMem((*new_li)->FilePath, org_li->FilePath, l);
    }

    if ( (0 == (*new_li)->FilePath) && (0 != org_li->FilePath) )
    {
      // handle scenarios, where original org_li->FilePath is 0 ?
      // in such a case we could not copy the filepath in the workaround above and will abort here
      // check all following FreePool(new_li->FilePath) statements that they are only called if not 0
		efi_status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to allocate FilePath for LoadedImageProtocol"));

        if (0 != (*new_li)->LoadOptions)
            GetBootServices()->FreePool((*new_li)->LoadOptions);

#ifdef CREATE_LI_BY_SELF
        FreePool(*new_li);
#else
    	CopyMem(*new_li, new_li_bak, sizeof(EFI_LOADED_IMAGE)); // restore orignal image data from Backup
        (void) GetBootServices()->CloseProtocol(*new_handle, &loaded_image_protocol, image_handle, 0);
        GetBootServices()->UnloadImage(*new_handle);
#endif
        return efi_status;
    }

    return EFI_SUCCESS;
}


/*
 * Locate the second stage bootloader and read it into a buffer
 */
static EFI_STATUS load_module(void **data,
			     unsigned int *datasize, CHAR16 *PathName, EFI_HANDLE volumeDeviceHandle)
{
    FUNCTION(load_module);

    EFI_FILE *root = 0;
    EFI_SIMPLE_FILE_SYSTEM_PROTOCOL *FileSystem = 0;
    EFI_GUID FsGuid = EFI_SIMPLE_FILE_SYSTEM_PROTOCOL_GUID;
    EFI_STATUS efi_status = GetBootServices()->OpenProtocol(volumeDeviceHandle, &FsGuid, (VOID **) &FileSystem, GetImageHandle(), 0, EFI_OPEN_PROTOCOL_BY_HANDLE_PROTOCOL);
    if (efi_status == EFI_SUCCESS)
    {
        efi_status = FileSystem->OpenVolume(FileSystem, &root);
        GetBootServices()->CloseProtocol(volumeDeviceHandle, &FsGuid, GetImageHandle(), 0);
    }

	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to open fs"));
        efi_status = EFI_NOT_FOUND; // unable to open volume -> executable not found
		return efi_status;
	}

	EFI_FILE *moduleFile = 0;
	efi_status = root->Open(root, &moduleFile, PathName,
				       EFI_FILE_MODE_READ, 0);

    root->Close(root);

	if (efi_status != EFI_SUCCESS) {
        efi_status = EFI_NOT_FOUND; // unable to open executable -> executable not found
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, (const wchar_t *)PathName));
		return efi_status;
	}

    // determine needed size for Info Buffer
    EFI_GUID file_info_id = EFI_FILE_INFO_ID;
	UINTN buffersize = 0;
	efi_status = moduleFile->GetInfo(moduleFile, &file_info_id, &buffersize, 0);

	if ((efi_status != EFI_BUFFER_TOO_SMALL) || (0 == buffersize)) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to get file info"));
        moduleFile->Close(moduleFile);
        if (EFI_SUCCESS == efi_status)
            efi_status = EFI_LOAD_ERROR;
		return efi_status;
	}

    // now allocate the buffer and get the info
	EFI_FILE_INFO *fileinfo = reinterpret_cast<EFI_FILE_INFO*>(AllocatePool(buffersize));

	if (!fileinfo) {
		efi_status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to allocate file info buffer"));
        moduleFile->Close(moduleFile);
		return efi_status;
	}

	efi_status = moduleFile->GetInfo(moduleFile, &file_info_id, &buffersize, fileinfo);

	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to get file info"));
        FreePool(fileinfo);
        moduleFile->Close(moduleFile);
		return efi_status;
	}

    const UINT64 fileSize = fileinfo->FileSize;
    // no more needed
    FreePool(fileinfo);

    // don't load very big files
    if (MaxFileSize < fileSize)
    {
        efi_status = EFI_UNSUPPORTED;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"File too big"));
        moduleFile->Close(moduleFile);
		return efi_status;
	}

	buffersize = static_cast<UINTN>(fileSize);

	*data = AllocatePool(buffersize);

	if (!*data) {
		efi_status = EFI_OUT_OF_RESOURCES;
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to allocate file buffer"));
        moduleFile->Close(moduleFile);
		return efi_status;
	}

    efi_status = moduleFile->Read(moduleFile, &buffersize, *data);

    // can be closed now
    moduleFile->Close(moduleFile);

	if ( (efi_status != EFI_SUCCESS) || (buffersize != static_cast<UINTN>(fileSize))) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unexpected return from initial read"));
        if (EFI_SUCCESS == efi_status)
            efi_status = EFI_LOAD_ERROR;

		FreePool(*data);
		*data = NULL;

        return efi_status;
	}

    // allocated data will be returned, must be freed by caller

	*datasize = static_cast<unsigned int>(buffersize);

	return EFI_SUCCESS;
}


static EFI_STATUS run_module(EFI_HANDLE image_handle, EFI_HANDLE volumeDeviceHandle, const CHAR16 *fileName, EFI_STATUS *executableResult, const char * VerifyModuleId)
{
    FUNCTION(run_module);

    BOOLEAN isDriver = FALSE;

    *executableResult = EFI_NOT_STARTED;

    // first get our Loaded Image protocol, we need it after loading the module, but if it fails we can spare unnecessary loading
    EFI_LOADED_IMAGE *li = 0;
	EFI_GUID loaded_image_protocol = LOADED_IMAGE_PROTOCOL;

	EFI_STATUS  efi_status = GetBootServices()->HandleProtocol(image_handle, &loaded_image_protocol, (void**)&li);

	if (efi_status != EFI_SUCCESS)
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to init protocol"));
		return efi_status;
	}

    CHAR16 * PathName = NULL;
	efi_status = generate_path(li->FilePath, fileName, &PathName, volumeDeviceHandle);

	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to generate path."));
#ifndef NoConsole
		setup_console(1);
		console_error((CHAR16*)L"Unable to generate path.", efi_status);
#endif
		return efi_status;
	}

	void *data = 0;
	unsigned int datasize = 0;

    efi_status = load_module(&data, &datasize, PathName, volumeDeviceHandle);

	if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to load image:"));
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, PathName));
#ifndef NoConsole
		setup_console(1);
		console_error2((CHAR16*)L"Failed to load image:", efi_status, PathName);
#endif
        if (0 != data)
            FreePool(data);

        return efi_status;
	}

    // MBA: now that we know the fileName is correct (verified by load_module), we can create the FilePath memory from it (using shimutil function)
    EFI_LOADED_IMAGE * new_li = 0, new_li_bak;
    EFI_HANDLE new_ImageHandle = 0;
    efi_status = create_imagehandle(image_handle, li, PathName, &new_ImageHandle, &new_li, &new_li_bak);
	(void) GetBootServices()->CloseProtocol(image_handle, &loaded_image_protocol, image_handle, 0);
    if (efi_status != EFI_SUCCESS)
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to create ImageHandle"));
        if (0 != data)
            FreePool(data);
        return efi_status;
	}

    // fills the Loaded image struct and sets entry_point
    EFI_IMAGE_ENTRY_POINT entry_point = 0;
	efi_status = handle_module(data, datasize, new_li, &entry_point, VerifyModuleId);

    if (new_li->ImageCodeType != EfiLoaderCode)
        isDriver = TRUE;

    // we now can free the loader buffer
    FreePool(data);

    if (efi_status != EFI_SUCCESS) {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Verification failed, could not load image:"));
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, PathName));
#ifndef NoConsole
		setup_console(1);
		console_error2((CHAR16*)L"Verification failed, could not load image:", efi_status, PathName);
#endif

        if (0 != new_li->FilePath)
            FreePool(new_li->FilePath);

        if (0 != new_li->LoadOptions)
            FreePool(new_li->LoadOptions);

#ifdef CREATE_LI_BY_SELF
        if (0 != new_li->FilePath)
            FreePool(new_li->FilePath);
        FreePool(new_li);
#else
    	CopyMem(new_li, &new_li_bak, sizeof(EFI_LOADED_IMAGE)); // restore orignal image data from Backup
        (void) GetBootServices()->CloseProtocol(new_ImageHandle, &loaded_image_protocol, image_handle, 0);
        GetBootServices()->UnloadImage(new_ImageHandle);
#endif

		return efi_status;
	}

#ifdef CREATE_LI_BY_SELF
    // final step we need to do here
    // MBA: UEFI spec says: if Handle is 0 a new Handle will be created
    efi_status = GetBootServices()->InstallProtocolInterface(&new_ImageHandle, &loaded_image_protocol, EFI_NATIVE_INTERFACE, new_li);
    if ( (efi_status != EFI_SUCCESS) || (0 == new_ImageHandle) )
    {
        SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Unable to install new LoadedImageProtocol"));

        GetBootServices()->FreePages(new_li->ImageBase, static_cast<UINTN>(EFI_SIZE_TO_PAGES(new_li->ImageSize)));

        if (0 != new_li->LoadOptions)
            FreePool(new_li->LoadOptions);

        if (0 != new_li->FilePath)
            FreePool(new_li->FilePath);
        FreePool(new_li);

        return efi_status;
	}
#endif

    // now call the module
	*executableResult = entry_point(new_ImageHandle, GetSystemTable());

    if (!isDriver || *executableResult != EFI_SUCCESS)
    {
#ifdef CREATE_LI_BY_SELF
        // MBA: UEFI Spec says: Handle is freed if last Protocol is uninstalled
        efi_status = GetBootServices()->UninstallProtocolInterface(new_ImageHandle, &loaded_image_protocol, new_li);
        if (EFI_SUCCESS == efi_status)
        {
            // free all the data
            GetBootServices()->FreePages((UINT64)new_li->ImageBase, EFI_SIZE_TO_PAGES(new_li->ImageSize));
            if (0 != new_li->FilePath)
                FreePool(new_li->FilePath);
            if (new_li->LoadOptions)
                FreePool(new_li->LoadOptions);
            FreePool(new_li);
        }
        else
        {
            // else: we could not uninstall the LoadedImage protocol so we keep all that memory so nobody can access invalid memory
            // TODO by Component Owner: do so or free in any case ?
            SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to uninstall protocol, memory not released"));
        }
#else
        GetBootServices()->FreePages((UINT64)new_li->ImageBase, (UINTN) EFI_SIZE_TO_PAGES(new_li->ImageSize));
        if (0 != new_li->FilePath)
            FreePool(new_li->FilePath);
        if (new_li->LoadOptions)
            FreePool(new_li->LoadOptions);

    	CopyMem(new_li, &new_li_bak, sizeof(EFI_LOADED_IMAGE)); // restore orignal image data from Backup
        (void) GetBootServices()->CloseProtocol(new_ImageHandle, &loaded_image_protocol, image_handle, 0);
        GetBootServices()->UnloadImage(new_ImageHandle);
#endif
    }
    else // driver
    {
        // extra work for drivers
        efi_status = ConnectAllHandles();
        if (efi_status != EFI_SUCCESS) {
            SGMError((SGMT_MAJOR, (unsigned long)efi_status, L"Failed to Connect all handles"));
        }
        // don't free the memory/Handle/ect. of a driver module
    }

    return efi_status;
}


// The one and only Function of the Shim Loader Library
// but it's just a wrapper around the more or less original Shim Loader function "init_grub" (renamed to run_module for better understanding)
extern "C" EFI_STATUS ExecuteFile(EFI_HANDLE volumeDeviceHandle, const CHAR16 *fileName, EFI_STATUS *executableResult, const char * VerifyModuleId)
{
    FUNCTION(ExecuteFile);

    if ((0 == volumeDeviceHandle) || (0 == fileName) || (0 == executableResult))
    {
        EFI_STATUS stat = EFI_INVALID_PARAMETER;
        SGMError((SGMT_MAJOR, (unsigned long)stat, L"Invalid input parameter"));
        return stat;
    }

    return run_module(GetImageHandle(), volumeDeviceHandle, fileName, executableResult, VerifyModuleId);
}
