/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#pragma once

#include <fwupdplugin.h>

#define FU_TYPE_LENOVO_DOCK_DEVICE (fu_lenovo_dock_device_get_type ())
G_DECLARE_FINAL_TYPE (FuLenovoDockDevice, fu_lenovo_dock_device, FU, LENOVO_DOCK_DEVICE, FuHidDevice)

struct _FuLenovoDockDeviceClass
{
	FuHidDeviceClass	parent_class;
};
