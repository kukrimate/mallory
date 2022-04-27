// SPDX-License-Identifier: BSD-2-Clause-Patent
/*
 * shim - trivial UEFI first-stage bootloader
 *
 * Copyright Red Hat, Inc
 */

/*   Chemical agents lend themselves to covert use in sabotage against
 * which it is exceedingly difficult to visualize any really effective
 * defense... I will not dwell upon this use of CBW because, as one
 * pursues the possibilities of such covert uses, one discovers that the
 * scenarios resemble that in which the components of a nuclear weapon
 * are smuggled into New York City and assembled in the basement of the
 * Empire State Building.
 *   In other words, once the possibility is recognized to exist, about
 * all that one can do is worry about it.
 *   -- Dr. Ivan L Bennett, Jr., testifying before the Subcommittee on
 *      National Security Policy and Scientific Developments, November 20,
 *      1969.
 */
#include "shim.h"

static EFI_SYSTEM_TABLE *systab;

EFI_SYSTEM_TABLE *
get_active_systab(void)
{
	if (systab)
		return systab;
	return ST;
}

static typeof(systab->BootServices->LoadImage) system_load_image;
static typeof(systab->BootServices->StartImage) system_start_image;
static typeof(systab->BootServices->Exit) system_exit;
#if defined(SIMULATE_ENABLED_STATE)
static typeof(systab->RuntimeServices->GetVariable) system_get_variable;
static typeof(systab->RuntimeServices->GetNextVariableName) system_get_next_variable_name;
static typeof(systab->RuntimeServices->SetVariable) system_set_variable;
#endif
#if !defined(DISABLE_EBS_PROTECTION)
static typeof(systab->BootServices->ExitBootServices) system_exit_boot_services;
#endif /* !defined(DISABLE_EBS_PROTECTION) */

static EFI_HANDLE last_loaded_image;

void
unhook_system_services(void)
{
	if (!systab)
		return;

	unhook_variable_services();

	systab->BootServices->LoadImage = system_load_image;
	systab->BootServices->StartImage = system_start_image;
#if defined(SIMULATE_ENABLED_STATE)
	systab->RuntimeServices->GetVariable = system_get_variable;
	systab->RuntimeServices->SetVariable = system_set_variable;
	systab->RuntimeServices->GetNextVariableName = system_get_next_variable_name;
#endif
#if !defined(DISABLE_EBS_PROTECTION)
	systab->BootServices->ExitBootServices = system_exit_boot_services;
#endif /* !defined(DISABLE_EBS_PROTECTION) */
	BS = systab->BootServices;
}

void
unhook_variable_services(void)
{
	if (!systab)
		return;

#if defined(SIMULATE_ENABLED_STATE)
	systab->RuntimeServices->GetVariable = system_get_variable;
	systab->RuntimeServices->SetVariable = system_set_variable;
	systab->RuntimeServices->GetNextVariableName = system_get_next_variable_name;
#endif
}

static EFI_STATUS EFIAPI
load_image(BOOLEAN BootPolicy, EFI_HANDLE ParentImageHandle,
	EFI_DEVICE_PATH *DevicePath, VOID *SourceBuffer,
	UINTN SourceSize, EFI_HANDLE *ImageHandle)
{
	EFI_STATUS efi_status;

	unhook_system_services();
	efi_status = BS->LoadImage(BootPolicy, ParentImageHandle, DevicePath,
				   SourceBuffer, SourceSize, ImageHandle);
	hook_system_services(systab);
	if (EFI_ERROR(efi_status))
		last_loaded_image = NULL;
	else
		last_loaded_image = *ImageHandle;
	return efi_status;
}

static EFI_STATUS EFIAPI
replacement_start_image(EFI_HANDLE image_handle, UINTN *exit_data_size, CHAR16 **exit_data)
{
	EFI_STATUS efi_status;
	unhook_system_services();
	unhook_variable_services();

	if (image_handle == last_loaded_image) {
		loader_is_participating = 1;
		uninstall_shim_protocols();
	}
	efi_status = BS->StartImage(image_handle, exit_data_size, exit_data);
	if (EFI_ERROR(efi_status)) {
		if (image_handle == last_loaded_image) {
			EFI_STATUS efi_status2 = install_shim_protocols();

			if (EFI_ERROR(efi_status2)) {
				console_print(L"Something has gone seriously wrong: %r\n",
					      efi_status2);
				console_print(L"shim cannot continue, sorry.\n");
				msleep(5000000);
				RT->ResetSystem(EfiResetShutdown,
						EFI_SECURITY_VIOLATION,
						0, NULL);
			}
		}
		hook_system_services(systab);
		hook_variable_services(systab);
		loader_is_participating = 0;
	}
	return efi_status;
}

#if defined(SIMULATE_ENABLED_STATE)
extern uint8_t simulated_pk[];
extern uint8_t simulated_kek[];
extern uint8_t simulated_db[];
extern uint8_t simulated_dbx[];
extern uint8_t simulated_setupmode[];
extern uint8_t simulated_secureboot[];

extern const uint32_t simulated_pk_size;
extern const uint32_t simulated_kek_size;
extern const uint32_t simulated_db_size;
extern const uint32_t simulated_dbx_size;
extern const uint32_t simulated_setupmode_size;
extern const uint32_t simulated_secureboot_size;

static const struct simulation {
	const CHAR16 name[32];
	EFI_GUID *guid;
	const uint8_t *data;
	const uint32_t *data_size;
	const uint32_t attrs;
	const EFI_STATUS set_variable_rc;
} simulations[] = {
	{ L"PK", &GV_GUID, simulated_pk, &simulated_pk_size, UEFI_VAR_NV_BS_RT, },
	{ L"KEK", &GV_GUID, simulated_kek, &simulated_kek_size, UEFI_VAR_NV_BS_RT, },
	{ L"SetupMode", &GV_GUID, simulated_setupmode, &simulated_setupmode_size, UEFI_VAR_NV_BS_RT, },
	{ L"SecureBoot", &GV_GUID, simulated_secureboot, &simulated_secureboot_size, UEFI_VAR_NV_BS_RT, },
	{ L"db", &SIG_DB, simulated_db, &simulated_db_size, UEFI_VAR_NV_BS_RT, },
	{ L"dbx", &SIG_DB, simulated_dbx, &simulated_dbx_size, UEFI_VAR_NV_BS_RT, },
	{ L"", NULL, NULL, 0, 0, }
};

static EFI_STATUS EFIAPI
replacement_get_variable(CHAR16 *variable_name, EFI_GUID *vendor_guid,
                         UINT32 *attributes, UINTN *data_size, VOID *data)
{
	unsigned int i;

	if (!variable_name || !vendor_guid || !data_size)
		return EFI_INVALID_PARAMETER;

	for (i = 0; simulations[i].name[0] != L'\0'; i++) {
		if (!StrCmp(simulations[i].name, variable_name) &&
		    !CompareGuid(simulations[i].guid, vendor_guid))
		{
			if (*data_size < *simulations[i].data_size) {
				*data_size = *simulations[i].data_size;
				return EFI_BUFFER_TOO_SMALL;
			}
			if (!data)
				return EFI_INVALID_PARAMETER;

			*data_size = *simulations[i].data_size;
			CopyMem(data, (void *)simulations[i].data, *data_size);
			if (attributes)
				*attributes = simulations[i].attrs;
			return EFI_SUCCESS;
		}
	}

	return system_get_variable(variable_name, vendor_guid, attributes,
	                           data_size, data);
}

static EFI_STATUS
update_gnvn(UINTN *name_size_out, CHAR16 *name_out, EFI_GUID *vendor_guid_out,
	    const CHAR16 * const name, const EFI_GUID * const vendor_guid)
{
	size_t namesz;

	namesz = StrSize(name);
	if (*name_size_out < namesz) {
		*name_size_out = namesz;
		return EFI_BUFFER_TOO_SMALL;
	}

	*name_size_out = namesz;
	CopyMem(name_out, (CHAR16 *)name, namesz);
	CopyMem(vendor_guid_out, (EFI_GUID *)vendor_guid, sizeof(EFI_GUID));
	return EFI_SUCCESS;
}

static EFI_STATUS EFIAPI
replacement_get_next_variable_name(UINTN *variable_name_size,
                                   CHAR16 *variable_name, EFI_GUID *vendor_guid)
{
	unsigned int i;
	bool found = false;

	if (!variable_name_size || !variable_name || !vendor_guid)
		return EFI_INVALID_PARAMETER;

	if (!*variable_name_size)
		return update_gnvn(variable_name_size, variable_name,
		                   vendor_guid, simulations[0].name,
		                   simulations[0].guid);

	for (i = 0; simulations[i].name[0] != L'\0'; i++) {
		if (found)
			return update_gnvn(variable_name_size, variable_name,
			                   vendor_guid, simulations[i].name,
			                   simulations[i].guid);
		if (!StrCmp(variable_name, simulations[i].name) &&
		    !CompareGuid(vendor_guid, simulations[i].guid))
		{
			found = true;
			continue;
		}
	}

	return system_get_next_variable_name(variable_name_size, variable_name,
	                                     vendor_guid);
}

static EFI_STATUS EFIAPI
replacement_set_variable(CHAR16 *variable_name, EFI_GUID *vendor_guid,
                         UINT32 attributes, UINTN data_size, VOID *data)
{
	unsigned int i;

	if (!variable_name || !vendor_guid || !attributes || !data_size ||
	    !data)
		return EFI_INVALID_PARAMETER;

	for (i = 0; simulations[i].name[0] != L'\0'; i++) {
		if (!StrCmp(variable_name, simulations[i].name) &&
		    !CompareGuid(vendor_guid, simulations[i].guid))
			return simulations[i].set_variable_rc;
	}

	return system_set_variable(variable_name, vendor_guid, attributes,
	                           data_size, data);
}
#endif

#if !defined(DISABLE_EBS_PROTECTION)
static EFI_STATUS EFIAPI
exit_boot_services(EFI_HANDLE image_key, UINTN map_key)
{
	if (loader_is_participating ||
	    verification_method == VERIFIED_BY_HASH) {
		unhook_system_services();
		EFI_STATUS efi_status;
		efi_status = BS->ExitBootServices(image_key, map_key);
		if (EFI_ERROR(efi_status))
			hook_system_services(systab);
		return efi_status;
	}

	console_print(L"Bootloader has not verified loaded image.\n");
	console_print(L"System is compromised.  halting.\n");
	msleep(5000000);
	RT->ResetSystem(EfiResetShutdown, EFI_SECURITY_VIOLATION, 0, NULL);
	return EFI_SECURITY_VIOLATION;
}
#endif /* !defined(DISABLE_EBS_PROTECTION) */

static EFI_STATUS EFIAPI
do_exit(EFI_HANDLE ImageHandle, EFI_STATUS ExitStatus,
	UINTN ExitDataSize, CHAR16 *ExitData)
{
	EFI_STATUS efi_status;

	shim_fini();

	restore_loaded_image();

	efi_status = BS->Exit(ImageHandle, ExitStatus,
			      ExitDataSize, ExitData);
	if (EFI_ERROR(efi_status)) {
		EFI_STATUS efi_status2 = shim_init();

		if (EFI_ERROR(efi_status2)) {
			console_print(L"Something has gone seriously wrong: %r\n",
				      efi_status2);
			console_print(L"shim cannot continue, sorry.\n");
			msleep(5000000);
			RT->ResetSystem(EfiResetShutdown,
					EFI_SECURITY_VIOLATION, 0, NULL);
		}
	}
	return efi_status;
}

void
hook_variable_services(EFI_SYSTEM_TABLE *local_systab)
{
#if defined(SIMULATE_ENABLED_STATE)
	if (!systab)
		systab = local_systab;
	BS = systab->BootServices;
	RT = systab->RuntimeServices;

	system_get_variable = systab->RuntimeServices->GetVariable;
	system_set_variable = systab->RuntimeServices->SetVariable;
	system_get_next_variable_name = systab->RuntimeServices->GetNextVariableName;
	systab->RuntimeServices->GetVariable = replacement_get_variable;
	systab->RuntimeServices->GetNextVariableName = replacement_get_next_variable_name;
	systab->RuntimeServices->SetVariable = replacement_set_variable;
#endif
}

void
hook_system_services(EFI_SYSTEM_TABLE *local_systab)
{
	systab = local_systab;
	BS = systab->BootServices;

	/* We need to hook various calls to make this work... */

	/* We need LoadImage() hooked so that fallback.c can load shim
	 * without having to fake LoadImage as well.  This allows it
	 * to call the system LoadImage(), and have us track the output
	 * and mark loader_is_participating in replacement_start_image.  This
	 * means anything added by fallback has to be verified by the system
	 * db, which we want to preserve anyway, since that's all launching
	 * through BDS gives us. */
	system_load_image = systab->BootServices->LoadImage;
	systab->BootServices->LoadImage = load_image;

	/* we need StartImage() so that we can allow chain booting to an
	 * image trusted by the firmware */
	system_start_image = systab->BootServices->StartImage;
	systab->BootServices->StartImage = replacement_start_image;

#if !defined(DISABLE_EBS_PROTECTION)
	/* we need to hook ExitBootServices() so a) we can enforce the policy
	 * and b) we can unwrap when we're done. */
	system_exit_boot_services = systab->BootServices->ExitBootServices;
	systab->BootServices->ExitBootServices = exit_boot_services;
#endif /* defined(DISABLE_EBS_PROTECTION) */
}

void
unhook_exit(void)
{
	systab->BootServices->Exit = system_exit;
	BS = systab->BootServices;
}

void
hook_exit(EFI_SYSTEM_TABLE *local_systab)
{
	systab = local_systab;
	BS = local_systab->BootServices;

	/* we need to hook Exit() so that we can allow users to quit the
	 * bootloader and still e.g. start a new one or run an internal
	 * shell. */
	system_exit = systab->BootServices->Exit;
	systab->BootServices->Exit = do_exit;
}
