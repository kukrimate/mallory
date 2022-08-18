// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * loadfile.c - implement EFI_LOAD_FILE2_PROTOCOL for linux's
 *		LINUX_EFI_INITRD_MEDIA_GUID device path support
 * Copyright Peter Jones <pjones@redhat.com>
 */

#include "loadfile.h"
#include "shim.h"

/*
 * gnu-efi does .Length stupidly, so we have to do stupid things as well.
 */
#define u16_to_u8_array(val)				\
	{						\
		(UINT8)(((UINT16)(val)) & 0xff),	\
		(UINT8)((((UINT16)(val)) & 0xff00) >> 8)\
	}

struct initrd_dev_path initrd_device_path = {
	.vendor = {
		.Header = {
			.Type = MEDIA_DEVICE_PATH,
			.SubType = MEDIA_VENDOR_DP,
			.Length = u16_to_u8_array(sizeof(VENDOR_DEVICE_PATH)),
		},
		.Guid = LINUX_EFI_INITRD_MEDIA_GUID_INITIALIZER,
	},
	.end = {
		.Type = END_DEVICE_PATH_TYPE,
		.SubType = END_ENTIRE_DEVICE_PATH_SUBTYPE,
		.Length = u16_to_u8_array(sizeof(EFI_DEVICE_PATH_PROTOCOL)),
	},
};

extern UINT8 _initrd_start;
extern UINT8 _initrd_end;

static EFI_STATUS EFIAPI
load_initrd_from_memory(EFI_LOAD_FILE2_PROTOCOL *this,
			EFI_DEVICE_PATH *path,
			BOOLEAN BootPolicy,
			UINTN *BufferSize,
			VOID *Buffer)
{
	VENDOR_DEVICE_PATH *vendor;
	EFI_DEVICE_PATH *end;
	UINTN sz = ((UINTN)&_initrd_end) - ((UINTN)&_initrd_start);

	if (this != &load_initrd_proto)
		return EFI_INVALID_PARAMETER;

	vendor = (VENDOR_DEVICE_PATH *)path;
	if ((DevicePathType(&vendor->Header) != MEDIA_DEVICE_PATH) ||
	    (DevicePathSubType(&vendor->Header) != MEDIA_VENDOR_DP) ||
	    (DevicePathNodeLength(&vendor->Header) != sizeof(VENDOR_DEVICE_PATH)) ||
	    CompareGuid(&vendor->Guid, &LINUX_EFI_INITRD_MEDIA_GUID) != 0)
		return EFI_INVALID_PARAMETER;

	end = NextDevicePathNode(path);
	if (!IsDevicePathEnd(end) ||
	    DevicePathNodeLength(end) != sizeof(EFI_DEVICE_PATH_PROTOCOL))
		return EFI_INVALID_PARAMETER;

	if (BootPolicy != FALSE)
		return EFI_INVALID_PARAMETER;

	if (!BufferSize)
		return EFI_INVALID_PARAMETER;

	if (!Buffer) {
		*BufferSize = sz;
		return EFI_SUCCESS;
	}

	if (*BufferSize < sz) {
		*BufferSize = sz;
		return EFI_BUFFER_TOO_SMALL;
	}

	CopyMem(Buffer, &_initrd_start, sz);
	return EFI_SUCCESS;
}

EFI_LOAD_FILE2_PROTOCOL load_initrd_proto = {
	load_initrd_from_memory,
};

static EFI_HANDLE load_initrd_handle;

EFI_STATUS
register_load_initrd(void)
{
	EFI_STATUS efi_status;

	if (_initrd_start == _initrd_end)
		return EFI_SUCCESS;

	efi_status = BS->InstallProtocolInterface(&load_initrd_handle,
						  &LINUX_EFI_INITRD_MEDIA_GUID,
						  EFI_NATIVE_INTERFACE,
						  &load_initrd_proto);

	return efi_status;
}

void
unregister_load_initrd(void)
{
	if (_initrd_start == _initrd_end)
		return;

	BS->UninstallProtocolInterface(load_initrd_handle,
				       &LINUX_EFI_INITRD_MEDIA_GUID,
				       &load_initrd_proto);
}

// vim:fenc=utf-8:tw=75:noet
