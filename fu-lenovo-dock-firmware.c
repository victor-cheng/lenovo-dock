/*
 * Copyright (C) 2021 Universal Global Scientific Industrial Co., Ltd.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>
#include <string.h>

#include "fu-lenovo-dock-firmware.h"

struct _FuLenovoDockFirmware {
	FuSrecFirmwareClass		 parent_instance;
	FuLenovoDockFileKind	 file_kind;
	FuLenovoDockDeviceKind	 device_kind;
	FuLenovoDockEepromCustomInfo cinfo;
};

G_DEFINE_TYPE (FuLenovoDockFirmware, fu_lenovo_dock_firmware, FU_TYPE_SREC_FIRMWARE)

FuLenovoDockFileKind
fu_lenovo_dock_firmware_get_file_type (FuLenovoDockFirmware *self)
{
	g_return_val_if_fail (FU_IS_LENOVO_DOCK_FIRMWARE (self), 0);
	return self->file_kind;
}

FuLenovoDockDeviceKind
fu_lenovo_dock_firmware_get_devtype (FuLenovoDockFirmware *self)
{
	g_return_val_if_fail (FU_IS_LENOVO_DOCK_FIRMWARE (self), 0);
	return self->device_kind;
}

guint8
fu_lenovo_dock_firmware_get_layout_version (FuLenovoDockFirmware *self)
{
	g_return_val_if_fail (FU_IS_LENOVO_DOCK_FIRMWARE (self), 0);
	return self->cinfo.LayoutVersion;
}

static void
fu_lenovo_dock_firmware_export (FuFirmware *firmware,
				      FuFirmwareExportFlags flags,
				      XbBuilderNode *bn)
{
	FuLenovoDockFirmware *self = FU_LENOVO_DOCK_FIRMWARE (firmware);
	fu_xmlb_builder_insert_kx (bn, "file_kind", self->file_kind);
	fu_xmlb_builder_insert_kx (bn, "device_kind", self->device_kind);
	fu_xmlb_builder_insert_kx (bn, "layout_signature", self->cinfo.LayoutSignature);
	fu_xmlb_builder_insert_kx (bn, "layout_version", self->cinfo.LayoutVersion);
	if (self->cinfo.LayoutVersion >= 1) {
		fu_xmlb_builder_insert_kx (bn, "vid", self->cinfo.VendorID);
		fu_xmlb_builder_insert_kx (bn, "pid", self->cinfo.ProductID);
		fu_xmlb_builder_insert_kx (bn, "rev", self->cinfo.RevisionID);
	}
}

typedef struct {
	const gchar	*str;
	guint32		 addr;
	guint32		 len;
} FuLenovoDockFirmwareBadblock;

static void
fu_lenovo_dock_firmware_badblock_add (GPtrArray *badblocks, const gchar *str, guint32 addr, guint32 len)
{
	FuLenovoDockFirmwareBadblock *bb = g_new0 (FuLenovoDockFirmwareBadblock, 1);
	g_debug ("created reserved range @0x%04x len:0x%x: %s", addr, len, str);
	bb->str = str;
	bb->addr = addr;
	bb->len = len;
	g_ptr_array_add (badblocks, bb);
}

static gboolean
fu_lenovo_dock_firmware_is_addr_valid (GPtrArray *badblocks, guint32 addr, guint32 len)
{
	for (guint j = 0; j < badblocks->len; j++) {
		FuLenovoDockFirmwareBadblock *bb = g_ptr_array_index (badblocks, j);
		if (addr <= bb->addr + bb->len - 1 &&
		    addr + len - 1 >= bb->addr) {
			g_debug ("addr @0x%04x len:0x%x invalid "
				 "as 0x%02x->0x%02x protected: %s",
				 addr, len, bb->addr, bb->addr + bb->len - 1, bb->str);
			return FALSE;
		}
	}
	return TRUE;
}

static gboolean
fu_lenovo_dock_firmware_is_record_valid (GPtrArray *badblocks, FuSrecFirmwareRecord *rcd)
{
	/* the entire record is not within an ignored range */
	return fu_lenovo_dock_firmware_is_addr_valid (badblocks, rcd->addr, rcd->buf->len);
}

static void
fu_lenovo_dock_firmware_avoid_badblocks (GPtrArray *badblocks, GPtrArray *records)
{
	g_autoptr(GPtrArray) records_new = g_ptr_array_new ();

	/* find records that include addresses with blocks we want to avoid */
	for (guint i = 0; i < records->len; i++) {
		FuSrecFirmwareRecord *rcd = g_ptr_array_index (records, i);
		FuSrecFirmwareRecord *rcd1;
		if (rcd->kind != FU_FIRMWARE_SREC_RECORD_KIND_S3_DATA_32)
			continue;
		if (fu_lenovo_dock_firmware_is_record_valid (badblocks, rcd)) {
			rcd1 = fu_srec_firmware_record_new (rcd->ln, rcd->kind, rcd->addr);
			g_byte_array_append (rcd1->buf, rcd->buf->data, rcd->buf->len);
			g_ptr_array_add (records_new, rcd1);
			continue;
		}
		g_debug ("splitting record @0x%04x len:0x%x as protected",
			 rcd->addr, rcd->buf->len);
		for (guint j = 0; j < rcd->buf->len; j++) {
			if (!fu_lenovo_dock_firmware_is_addr_valid (badblocks, rcd->addr + j, 0x1))
				continue;
			rcd1 = fu_srec_firmware_record_new (rcd->ln, rcd->kind, rcd->addr + j);
			g_byte_array_append (rcd1->buf, rcd->buf->data + j, 0x1);
			g_ptr_array_add (records_new, rcd1);
		}
	}

	/* swap the old set of records with the new records */
	g_ptr_array_set_size (records, 0);
	for (guint i = 0; i < records_new->len; i++) {
		FuSrecFirmwareRecord *rcd1 = g_ptr_array_index (records_new, i);
		g_ptr_array_add (records, rcd1);
	}
}

static gboolean
fu_lenovo_dock_firmware_parse (FuFirmware *firmware,
				     GBytes *fw,
				     guint64 addr_start,
				     guint64 addr_end,
				     FwupdInstallFlags flags,
				     GError **error)
{
	g_debug("USI, fu_lenovo_dock_firmware_parse");

	FuLenovoDockFirmware *self = FU_LENOVO_DOCK_FIRMWARE (firmware);
	GPtrArray *records = fu_srec_firmware_get_records (FU_SREC_FIRMWARE (firmware));
	guint8 dev_kind_candidate = G_MAXUINT8;
	g_autofree guint8 *shadow = g_malloc0 (FU_LENOVO_DOCK_EEPROM_SHADOW_SIZE);

	/* copy shadow EEPROM */
	for (guint i = 0; i < records->len; i++) {
		FuSrecFirmwareRecord *rcd = g_ptr_array_index (records, i);
		if (rcd->kind != FU_FIRMWARE_SREC_RECORD_KIND_S3_DATA_32)
			continue;
		if (rcd->addr > FU_LENOVO_DOCK_EEPROM_SHADOW_SIZE)
			continue;
		if (rcd->buf->len == 0) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "record 0x%x had zero size", i);
			return FALSE;
		}
		if (!fu_memcpy_safe (shadow, FU_LENOVO_DOCK_EEPROM_SHADOW_SIZE, rcd->addr, /* dst */
				     rcd->buf->data, rcd->buf->len, 0x0, /* src */
				     rcd->buf->len, error))
			return FALSE;
	}

	/* parse EEPROM map */
	if (!fu_memcpy_safe ((guint8 *) &self->cinfo, sizeof(FuLenovoDockEepromCustomInfo), 0x0, /* dst */
			     shadow, FU_LENOVO_DOCK_EEPROM_SHADOW_SIZE, FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET, /* src */
			     sizeof(FuLenovoDockEepromCustomInfo), error))
		return FALSE;

	/* just layout version byte is not enough in case of old CX20562 patch
	 * files that could have non-zero value of the Layout version */
	if (shadow[FU_LENOVO_DOCK_FIRMWARE_SIGNATURE_OFFSET] == FU_LENOVO_DOCK_SIGNATURE_BYTE) {
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2070x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2070X_FW;
		g_debug ("FileKind: CX2070x (FW)");
	} else if (shadow[FU_LENOVO_DOCK_EEPROM_PATCH_SIGNATURE_ADDRESS] == FU_LENOVO_DOCK_SIGNATURE_PATCH_BYTE) {
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2070x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2070X_PATCH;
		g_debug ("FileKind: CX2070x (Patch)");
	} else {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "USI, CX20562 is not supported");
		return FALSE;
	}
	for (guint i = records->len - 3; i < records->len; i++) {
		FuSrecFirmwareRecord *rcd = g_ptr_array_index (records, i);
		if (rcd->kind == FU_FIRMWARE_SREC_RECORD_KIND_S9_TERMINATION_16)
			continue;
		if (rcd->buf->len < 2)
			continue;
		if (memcmp (rcd->buf->data, "CX", 2) == 0) {
			dev_kind_candidate = rcd->buf->data[2];
			g_debug ("DeviceKind signature suspected 0x%0x", dev_kind_candidate);
			break;
		}
	}

	/* check the signature character to see if it defines the device */
	switch (dev_kind_candidate) {
	case '2':	/* fallthrough */	/* CX2070x */
	case '4':				/* CX2070x-21Z */
	case '6':				/* CX2070x-21Z */
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2070x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2070X_PATCH;
		g_debug ("FileKind: CX2070x overwritten from signature");
		break;
	case '3':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2077x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2077X_PATCH;
		g_debug ("FileKind: CX2077x overwritten from signature");
		break;
	case '5':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2076x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2076X_PATCH;
		g_debug ("FileKind: CX2076x overwritten from signature");
		break;
	case '7':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2085x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2085X_PATCH;
		g_debug ("FileKind: CX2085x overwritten from signature");
		break;
	case '8':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2089x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2089X_PATCH;
		g_debug ("FileKind: CX2089x overwritten from signature");
		break;
	case '9':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2098x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2098X_PATCH;
		g_debug ("FileKind: CX2098x overwritten from signature");
		break;
	case 'A':
		self->device_kind = FU_LENOVO_DOCK_DEVICE_KIND_CX2198x;
		self->file_kind = FU_LENOVO_DOCK_FILE_KIND_CX2198X_PATCH;
		g_debug ("FileKind: CX2198x overwritten from signature");
		break;
	default:
		/* probably future devices */
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "DeviceKind signature invalid 0x%x", dev_kind_candidate);
		return FALSE;
	}

	/* ignore records with protected content */
	if (self->cinfo.LayoutVersion >= 1) {
		g_autoptr(GPtrArray) badblocks = g_ptr_array_new_with_free_func (g_free);

		/* add standard ranges to ignore */
		fu_lenovo_dock_firmware_badblock_add (badblocks, "test mark", 0x00BC, 0x02);
		fu_lenovo_dock_firmware_badblock_add (badblocks, "application status",
						  FU_LENOVO_DOCK_EEPROM_APP_STATUS_ADDRESS, 1);
		fu_lenovo_dock_firmware_badblock_add (badblocks, "boot bytes",
						  FU_LENOVO_DOCK_EEPROM_VALIDITY_SIGNATURE_OFFSET,
						  sizeof(FuLenovoDockEepromValiditySignature) + 1);

		/* serial number address and also string pointer itself if set */
		if (self->cinfo.SerialNumberStringAddress != 0x0) {
			FuLenovoDockEepromPtr addr_tmp;
			FuLenovoDockEepromPtr addr_str;
			addr_tmp = FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET +
					G_STRUCT_OFFSET(FuLenovoDockEepromCustomInfo,
							SerialNumberStringAddress);
			fu_lenovo_dock_firmware_badblock_add (badblocks, "serial number",
							  addr_tmp, sizeof(FuLenovoDockEepromPtr));
			memcpy (&addr_str, shadow + addr_tmp, sizeof(addr_str));
			fu_lenovo_dock_firmware_badblock_add (badblocks, "serial number data",
							  addr_str, shadow[addr_str]);
		}
		fu_lenovo_dock_firmware_avoid_badblocks (badblocks, records);
	}

	/* this isn't used, but it seems a good thing to add */
	fu_firmware_set_bytes (firmware, fw);
	return TRUE;
}

static void
fu_lenovo_dock_firmware_init (FuLenovoDockFirmware *self)
{
}

static void
fu_lenovo_dock_firmware_class_init (FuLenovoDockFirmwareClass *klass)
{
	FuFirmwareClass *klass_firmware = FU_FIRMWARE_CLASS (klass);
	klass_firmware->parse = fu_lenovo_dock_firmware_parse;
	klass_firmware->export = fu_lenovo_dock_firmware_export;
}

FuFirmware *
fu_lenovo_dock_firmware_new (void)
{
	return FU_FIRMWARE (g_object_new (FU_TYPE_LENOVO_DOCK_FIRMWARE, NULL));
}
