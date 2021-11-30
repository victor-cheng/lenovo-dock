/*
 * Copyright (C) 2021 Universal Global Scientific Industrial Co., Ltd.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */
//TEST
#pragma once

#include <fwupdplugin.h>

/* usb */
#define FU_LENOVO_DOCK_INPUT_REPORT_SIZE			64
#define FU_LENOVO_DOCK_OUTPUT_REPORT_SIZE			64
#define FU_LENOVO_DOCK_USB_TIMEOUT				2000 /* ms */

/* commands */
#define FU_LENOVO_DOCK_MEM_WRITEID				0x4
#define FU_LENOVO_DOCK_MEM_READID				0x5

//USI-->
#if 1
typedef enum {
	FU_LENOVO_DOCK_DEVICE_KIND_UNKNOWN,
	FU_LENOVO_DOCK_DEVICE_KIND_CX20562		= 20562,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2070x		= 20700,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2077x		= 20770,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2076x		= 20760,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2085x		= 20850,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2089x		= 20890,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2098x		= 20980,
	FU_LENOVO_DOCK_DEVICE_KIND_CX2198x		= 21980,
	FU_LENOVO_DOCK_DEVICE_KIND_LAST
} FuLenovoDockDeviceKind;

typedef enum {
	FU_LENOVO_DOCK_MEM_KIND_EEPROM,
	FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
	FU_LENOVO_DOCK_MEM_KIND_CPX_ROM,
	FU_LENOVO_DOCK_MEM_KIND_LAST
} FuLenovoDockMemKind;
#endif
//<--USI

/* EEPROM */
#define FU_LENOVO_DOCK_EEPROM_VALIDITY_SIGNATURE_OFFSET	0x0000
#define FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET		0x0020
#define FU_LENOVO_DOCK_EEPROM_CPX_PATCH_VERSION_ADDRESS	0x0022
#define FU_LENOVO_DOCK_EEPROM_CPX_PATCH2_VERSION_ADDRESS	0x0176
#define FU_LENOVO_DOCK_EEPROM_STORAGE_SIZE_ADDRESS	0x0005
#define FU_LENOVO_DOCK_EEPROM_STORAGE_PADDING_SIZE	0x4 /* bytes */

#define FU_LENOVO_DOCK_DEVICE_CAPABILITIES_STRIDX		50
#define FU_LENOVO_DOCK_DEVICE_CAPABILITIES_BYTE		0x03
#define FU_LENOVO_DOCK_MAGIC_BYTE				'L'
#define FU_LENOVO_DOCK_SIGNATURE_BYTE			'S'
#define FU_LENOVO_DOCK_SIGNATURE_PATCH_BYTE		'P'
#define FU_LENOVO_DOCK_REG_FIRMWARE_PARK_ADDR		0x1000
#define FU_LENOVO_DOCK_REG_FIRMWARE_VERSION_ADDR		0x1001
#define FU_LENOVO_DOCK_REG_RESET_ADDR			0x0400
#define FU_LENOVO_DOCK_EEPROM_SHADOW_SIZE			(8 * 1024)

typedef guint16 FuLenovoDockEepromPtr;
typedef struct __attribute__ ((packed)) {
	FuLenovoDockEepromPtr	 PatchVersionStringAddress;
	guint8				 CpxPatchVersion[3];
	guint8				 SpxPatchVersion[4];
	guint8				 LayoutSignature;
	guint8				 LayoutVersion;
	guint8				 ApplicationStatus;
	guint16				 VendorID;
	guint16				 ProductID;
	guint16				 RevisionID;
	FuLenovoDockEepromPtr	 LanguageStringAddress;
	FuLenovoDockEepromPtr	 ManufacturerStringAddress;
	FuLenovoDockEepromPtr	 ProductStringAddress;
	FuLenovoDockEepromPtr	 SerialNumberStringAddress;
} FuLenovoDockEepromCustomInfo;

#define FU_LENOVO_DOCK_EEPROM_APP_STATUS_ADDRESS		(FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET + G_STRUCT_OFFSET(FuLenovoDockEepromCustomInfo, ApplicationStatus))
#define FU_LENOVO_DOCK_EEPROM_LAYOUT_SIGNATURE_ADDRESS	(FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET + G_STRUCT_OFFSET(FuLenovoDockEepromCustomInfo, LayoutSignature))
#define FU_LENOVO_DOCK_EEPROM_LAYOUT_VERSION_ADDRESS	(FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET + G_STRUCT_OFFSET(FuLenovoDockEepromCustomInfo, LayoutVersion))

typedef struct __attribute__ ((packed)) {
	guint8			 Length;
	guint8			 Type;
} FuLenovoDockEepromStringHeader;

typedef struct __attribute__ ((packed)) {
	guint8			 PatchSignature;
	FuLenovoDockEepromPtr	 PatchAddress;
} FuLenovoDockEepromPatchInfo;

typedef struct __attribute__ ((packed)) {
	guint8			 MagicByte;
	guint8			 EeepromSizeCode;
} FuLenovoDockEepromValiditySignature;

#define FU_LENOVO_DOCK_EEPROM_PATCH_INFO_OFFSET		0x0014
#define FU_LENOVO_DOCK_EEPROM_PATCH_INFO_SIZE		(sizeof(FuLenovoDockEepromPatchInfo))
#define FU_LENOVO_DOCK_EEPROM_PATCH_SIGNATURE_ADDRESS	(FU_LENOVO_DOCK_EEPROM_PATCH_INFO_OFFSET + G_STRUCT_OFFSET(FuLenovoDockEepromPatchInfo, PatchSignature))
#define FU_LENOVO_DOCK_EEPROM_PATCH_PTR_ADDRESS		(FU_LENOVO_DOCK_EEPROM_PATCH_INFO_OFFSET + G_STRUCT_OFFSET(FuLenovoDockEepromPatchInfo, PatchAddress))
#define FU_LENOVO_DOCK_FIRMWARE_SIGNATURE_OFFSET		(FU_LENOVO_DOCK_EEPROM_VALIDITY_SIGNATURE_OFFSET + sizeof(FuLenovoDockEepromValiditySignature))
