// SPDX-License-Identifier: BSD-2-Clause-Patent

#include "shim.h"

EFI_GUID BDS_GUID = { 0x8108ac4e, 0x9f11, 0x4d59, { 0x85, 0x0e, 0xe2, 0x1a, 0x52, 0x2c, 0x59, 0xb2 } };
EFI_GUID GV_GUID = EFI_GLOBAL_VARIABLE;
EFI_GUID SIG_DB = { 0xd719b2cb, 0x3d3a, 0x4596, {0xa3, 0xbc, 0xda, 0xd0,  0xe, 0x67, 0x65, 0x6f }};
EFI_GUID X509_GUID =   { 0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} };
EFI_GUID RSA2048_GUID = { 0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} };
EFI_GUID PKCS7_GUID = { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} };
EFI_GUID IMAGE_PROTOCOL = LOADED_IMAGE_PROTOCOL;
EFI_GUID EFI_FILE_INFO_GUID = EFI_FILE_INFO_ID;
EFI_GUID EFI_FILE_SYSTEM_INFO_GUID = EFI_FILE_SYSTEM_INFO_ID;
EFI_GUID EFI_CERT_RSA2048_GUID = { 0x3c5766e8, 0x269c, 0x4e34, {0xaa, 0x14, 0xed, 0x77, 0x6e, 0x85, 0xb3, 0xb6} };
EFI_GUID EFI_CERT_SHA1_GUID = { 0x826ca512, 0xcf10, 0x4ac9, {0xb1, 0x87, 0xbe, 0x1, 0x49, 0x66, 0x31, 0xbd }};
EFI_GUID EFI_CERT_SHA256_GUID  = { 0xc1c41626, 0x504c, 0x4092, { 0xac, 0xa9, 0x41, 0xf9, 0x36, 0x93, 0x43, 0x28 } };
EFI_GUID EFI_CERT_SHA224_GUID = { 0xb6e5233, 0xa65c, 0x44c9, {0x94, 0x7, 0xd9, 0xab, 0x83, 0xbf, 0xc8, 0xbd} };
EFI_GUID EFI_CERT_SHA384_GUID = { 0xff3e5307, 0x9fd0, 0x48c9, {0x85, 0xf1, 0x8a, 0xd5, 0x6c, 0x70, 0x1e, 0x1} };
EFI_GUID EFI_CERT_SHA512_GUID = { 0x93e0fae, 0xa6c4, 0x4f50, {0x9f, 0x1b, 0xd4, 0x1e, 0x2b, 0x89, 0xc1, 0x9a} };
EFI_GUID EFI_CERT_TYPE_PKCS7_GUID = { 0x4aafd29d, 0x68df, 0x49ee, {0x8a, 0xa9, 0x34, 0x7d, 0x37, 0x56, 0x65, 0xa7} };
EFI_GUID EFI_CERT_TYPE_RSA2048_SHA256_GUID = { 0xa7717414, 0xc616, 0x4977, {0x94, 0x20, 0x84, 0x47, 0x12, 0xa7, 0x35, 0xbf } };
EFI_GUID EFI_CERT_TYPE_X509_GUID = { 0xa5c059a1, 0x94e4, 0x4aa7, {0x87, 0xb5, 0xab, 0x15, 0x5c, 0x2b, 0xf0, 0x72} };
EFI_GUID EFI_CONSOLE_CONTROL_GUID = { 0xf42f7782, 0x12e, 0x4c12, {0x99, 0x56, 0x49, 0xf9, 0x43, 0x4, 0xf7, 0x21} };
EFI_GUID EFI_HTTP_BINDING_GUID = { 0xbdc8e6af, 0xd9bc, 0x4379, {0xa7, 0x2a, 0xe0, 0xc4, 0xe7, 0x5d, 0xae, 0x1c } };
EFI_GUID EFI_HTTP_PROTOCOL_GUID = { 0x7a59b29b, 0x910b, 0x4171, {0x82, 0x42, 0xa8, 0x5a, 0x0d, 0xf2, 0x5b, 0x5b } };
EFI_GUID EFI_IP4_CONFIG2_GUID = { 0x5b446ed1, 0xe30b, 0x4faa, {0x87, 0x1a, 0x36, 0x54, 0xec, 0xa3, 0x60, 0x80 } };
EFI_GUID EFI_IP6_CONFIG_GUID = { 0x937fe521, 0x95ae, 0x4d1a, {0x89, 0x29, 0x48, 0xbc, 0xd9, 0x0a, 0xd3, 0x1a } };
EFI_GUID EFI_LOADED_IMAGE_GUID = EFI_LOADED_IMAGE_PROTOCOL_GUID;
EFI_GUID EFI_TPM_GUID = { 0xf541796d, 0xa62e, 0x4954, {0xa7, 0x75, 0x95, 0x84, 0xf6, 0x1b, 0x9c, 0xdd } };
EFI_GUID EFI_TPM2_GUID = { 0x607f766c, 0x7455, 0x42be, {0x93, 0x0b, 0xe4, 0xd7, 0x6d, 0xb2, 0x72, 0x0f } };
EFI_GUID EFI_CC_MEASUREMENT_PROTOCOL_GUID = { 0x96751a3d, 0x72f4, 0x41a6, {0xa7, 0x94, 0xed, 0x5d, 0x0e, 0x67, 0xae, 0x6b } };
EFI_GUID EFI_SECURE_BOOT_DB_GUID =  { 0xd719b2cb, 0x3d3a, 0x4596, { 0xa3, 0xbc, 0xda, 0xd0, 0x0e, 0x67, 0x65, 0x6f } };
EFI_GUID EFI_SIMPLE_FILE_SYSTEM_GUID = SIMPLE_FILE_SYSTEM_PROTOCOL;
EFI_GUID SECURITY_PROTOCOL_GUID = { 0xA46423E3, 0x4617, 0x49f1, {0xB9, 0xFF, 0xD1, 0xBF, 0xA9, 0x11, 0x58, 0x39 } };
EFI_GUID SECURITY2_PROTOCOL_GUID = { 0x94ab2f58, 0x1438, 0x4ef1, {0x91, 0x52, 0x18, 0x94, 0x1a, 0x3a, 0x0e, 0x68 } };
EFI_GUID EFI_MEMORY_ATTRIBUTE_PROTOCOL_GUID = { 0xf4560cf6, 0x40ec, 0x4b4a, {0xa1, 0x92, 0xbf, 0x1d, 0x57, 0xd0, 0xb1, 0x89} };
EFI_GUID SHIM_LOCK_GUID = {0x605dab50, 0xe046, 0x4300, {0xab, 0xb6, 0x3d, 0xd8, 0x10, 0xdd, 0x8b, 0x23 } };
EFI_GUID MOK_VARIABLE_STORE = {0xc451ed2b, 0x9694, 0x45d3, {0xba, 0xba, 0xed, 0x9f, 0x89, 0x88, 0xa3, 0x89} };
EFI_GUID LINUX_EFI_INITRD_MEDIA_GUID = {0x5568e427, 0x68fc, 0x4f3d, { 0xac, 0x74, 0xca, 0x55, 0x52, 0x31, 0xcc, 0x68 } };
