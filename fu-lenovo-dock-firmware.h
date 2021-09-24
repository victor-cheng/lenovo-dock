/*
 * Copyright (C) 2021 Universal Global Scientific Industrial Co., Ltd.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#include "fu-lenovo-dock-common.h"

#define FU_TYPE_LENOVO_DOCK_FIRMWARE (fu_lenovo_dock_firmware_get_type ())
G_DECLARE_FINAL_TYPE (FuLenovoDockFirmware, fu_lenovo_dock_firmware, FU, LENOVO_DOCK_FIRMWARE, FuSrecFirmware)

typedef enum {
	FU_LENOVO_DOCK_FILE_KIND_UNKNOWN,
	FU_LENOVO_DOCK_FILE_KIND_CX2070X_FW,
	FU_LENOVO_DOCK_FILE_KIND_CX2070X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2077X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2076X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2085X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2089X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2098X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_CX2198X_PATCH,
	FU_LENOVO_DOCK_FILE_KIND_LAST
} FuLenovoDockFileKind;

FuFirmware			*fu_lenovo_dock_firmware_new			(void);
FuLenovoDockFileKind		fu_lenovo_dock_firmware_get_file_type		(FuLenovoDockFirmware	*self);
FuLenovoDockDeviceKind	 	fu_lenovo_dock_firmware_get_devtype		(FuLenovoDockFirmware	*self);
guint8				fu_lenovo_dock_firmware_get_layout_version	(FuLenovoDockFirmware	*self);
