/*
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>

#include "fu-lenovo-dock-device.h"
#include "fu-lenovo-dock-firmware.h"

void
fu_plugin_init (FuPlugin *plugin)
{
	g_debug("USI, plugin init");

	FuContext *ctx = fu_plugin_get_context (plugin);
	fu_plugin_set_build_hash (plugin, FU_BUILD_HASH);
	fu_plugin_add_device_gtype (plugin, FU_TYPE_LENOVO_DOCK_DEVICE);
	fu_plugin_add_firmware_gtype (plugin, NULL, FU_TYPE_LENOVO_DOCK_FIRMWARE);
	fu_context_add_quirk_key (ctx, "LenovoDockOption");
}

gboolean
fu_plugin_write_firmware(FuPlugin *plugin,
                         FuDevice *device,
                         GBytes *blob_fw,
                         FwupdInstallFlags flags,
                         GError **error)
{
	g_debug("USI, LenovoDock fu_plugin_write_firmware");
	return TRUE;

        FuDevice *parent = fu_device_get_parent (device);
        g_autoptr(FuDeviceLocker) locker = NULL;
        locker = fu_device_locker_new (parent != NULL ? parent : device, error);
        if (locker == NULL)
                return FALSE;
        return fu_device_write_firmware (device, blob_fw, flags, error);
}

