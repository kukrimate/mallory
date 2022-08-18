// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * loadfile.h - implement EFI_LOAD_FILE2_PROTOCOL for linux's
 *		LINUX_EFI_INITRD_MEDIA_GUID device path support
 * Copyright Peter Jones <pjones@redhat.com>
 */

#ifndef SHIM_LOADFILE_H_
#define SHIM_LOADFILE_H_

#include "shim.h"
#include <efidevp.h>

extern EFI_LOAD_FILE2_PROTOCOL load_initrd_proto;

struct initrd_dev_path {
	VENDOR_DEVICE_PATH vendor;
	EFI_DEVICE_PATH_PROTOCOL end;
} PACKED;
extern struct initrd_dev_path initrd_device_path;

extern EFI_STATUS register_load_initrd(void);
extern void unregister_load_initrd(void);

#endif /* !SHIM_LOADFILE_H_ */
// vim:fenc=utf-8:tw=75:noet
