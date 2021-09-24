/*
 * Copyright (C) 2021 Universal Global Scientific Industrial Co., Ltd.
 * Copyright (C) 2019 Richard Hughes <richard@hughsie.com>
 *
 * SPDX-License-Identifier: LGPL-2.1+
 */

#include "config.h"

#include <fwupdplugin.h>
#include <string.h>

#include "fu-lenovo-dock-common.h"
#include "fu-lenovo-dock-device.h"
#include "fu-lenovo-dock-firmware.h"
struct _FuLenovoDockDevice
{
	FuHidDevice		 parent_instance;
	guint32			 chip_id_base;
	guint32			 chip_id;
	gboolean		 serial_number_set;
	gboolean		 sw_reset_supported;
	guint32			 eeprom_layout_version;
	guint32			 eeprom_patch2_valid_addr;
	guint32			 eeprom_patch_valid_addr;
	guint32			 eeprom_storage_address;
	guint32			 eeprom_storage_sz;
	guint32			 eeprom_sz;
	guint8			 patch_level;

	guint32			bcd_version;
	guint8			lenovo_dock_option;
};

G_DEFINE_TYPE (FuLenovoDockDevice, fu_lenovo_dock_device, FU_TYPE_HID_DEVICE)

static void
fu_lenovo_dock_device_to_string (FuDevice *device, guint idt, GString *str)
{
//	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
}

static gboolean
fu_lenovo_dock_device_output_report (FuLenovoDockDevice *self,
					   guint8 *buf,
					   guint16 bufsz,
					   GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_output_report");

	/* weird */
	if (buf[0] == 0x0) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "report 0 not supported");
		return FALSE;
	}
	/* to device */
	return fu_hid_device_set_report (FU_HID_DEVICE (self), buf[0],
					 buf, bufsz,
					 FU_LENOVO_DOCK_USB_TIMEOUT,
					 FU_HID_DEVICE_FLAG_RETRY_FAILURE,
					 error);
}

static gboolean
fu_lenovo_dock_device_input_report (FuLenovoDockDevice *self,
					  guint8 ReportID,
					  guint8 *buf,
					  guint16 bufsz,
					  GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_input_report");
	return fu_hid_device_get_report (FU_HID_DEVICE (self), ReportID,
					 buf, bufsz,
					 FU_LENOVO_DOCK_USB_TIMEOUT,
					 FU_HID_DEVICE_FLAG_RETRY_FAILURE,
					 error);
}

typedef enum {
	FU_LENOVO_DOCK_OPERATION_READ,
	FU_LENOVO_DOCK_OPERATION_WRITE,
	FU_LENOVO_DOCK_OPERATION_LAST
} FuLenovoDockOperation;

typedef enum {
	FU_LENOVO_DOCK_OPERATION_FLAG_NONE		= 0,
	FU_LENOVO_DOCK_OPERATION_FLAG_VERIFY		= (1 << 4),
} FuLenovoDockOperationFlags;

static gboolean
fu_lenovo_dock_device_operation (FuLenovoDockDevice *self,
				       FuLenovoDockOperation operation,
				       FuLenovoDockMemKind mem_kind,
				       guint32 addr,
				       guint8 *buf,
				       guint32 bufsz,
				       FuLenovoDockOperationFlags flags,
				       GError **error)
{
	const guint32 idx_read = 0x1;
	const guint32 idx_write = 0x5;
	const guint32 payload_max = 0x20;
	guint32 size = 0x02800;
	g_autoptr(GPtrArray) chunks = NULL;

	g_return_val_if_fail (bufsz > 0, FALSE);
	g_return_val_if_fail (buf != NULL, FALSE);

	/* check if memory operation is supported by device */
	if (operation == FU_LENOVO_DOCK_OPERATION_WRITE &&
	    mem_kind == FU_LENOVO_DOCK_MEM_KIND_CPX_ROM) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "trying to write unwritable section %u",
			     mem_kind);
		return FALSE;
	}

	/* check memory address - should be within valid range */
	if (mem_kind == FU_LENOVO_DOCK_MEM_KIND_EEPROM)
		size = 0x20000;
	if (addr > size) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "address out of range 0x%x < 0x%x",
			     addr, size);
		return FALSE;
	}

	/* send to hardware */
	chunks = fu_chunk_array_mutable_new (buf, bufsz, addr, 0x0, payload_max);
	for (guint i = 0; i < chunks->len; i++) {
		FuChunk *chk = g_ptr_array_index (chunks, i);
		guint8 inbuf[FU_LENOVO_DOCK_INPUT_REPORT_SIZE] = { 0 };
		guint8 outbuf[FU_LENOVO_DOCK_OUTPUT_REPORT_SIZE] = { 0 };

		/* first byte is always report ID */
		outbuf[0] = FU_LENOVO_DOCK_MEM_WRITEID;

		/* set memory address and payload length (if relevant) */
		if (fu_chunk_get_address (chk) >= 64 * 1024)
			outbuf[1] |= 1 << 4;
		outbuf[2] = fu_chunk_get_data_sz (chk);
		fu_common_write_uint16 (outbuf + 3, fu_chunk_get_address (chk), G_BIG_ENDIAN);

		/* set memtype */
		if (mem_kind == FU_LENOVO_DOCK_MEM_KIND_EEPROM)
			outbuf[1] |= 1 << 5;

		/* fill the report payload part */
		if (operation == FU_LENOVO_DOCK_OPERATION_WRITE) {
			outbuf[1] |= 1 << 6;
			if (!fu_memcpy_safe (outbuf, sizeof(outbuf), idx_write, /* dst */
					     fu_chunk_get_data (chk),
					     fu_chunk_get_data_sz (chk), 0x0, /* src */
					     fu_chunk_get_data_sz (chk), error))
				return FALSE;
		}
		if (!fu_lenovo_dock_device_output_report (self, outbuf, sizeof(outbuf), error))
			return FALSE;

		/* issue additional write directive to read */
		if (operation == FU_LENOVO_DOCK_OPERATION_WRITE &&
		    flags & FU_LENOVO_DOCK_OPERATION_FLAG_VERIFY) {
			outbuf[1] &= ~(1 << 6);
			if (!fu_lenovo_dock_device_output_report (self, outbuf, sizeof(outbuf), error))
				return FALSE;
		}
		if (operation == FU_LENOVO_DOCK_OPERATION_READ ||
		    flags & FU_LENOVO_DOCK_OPERATION_FLAG_VERIFY) {
			if (!fu_lenovo_dock_device_input_report (self,
							       FU_LENOVO_DOCK_MEM_READID,
							       inbuf, sizeof(inbuf),
							       error))
				return FALSE;
		}
		if (operation == FU_LENOVO_DOCK_OPERATION_WRITE &&
		    flags & FU_LENOVO_DOCK_OPERATION_FLAG_VERIFY) {
			if (!fu_common_bytes_compare_raw (outbuf + idx_write, payload_max,
							  inbuf + idx_read, payload_max,
							  error)) {
				g_prefix_error (error,
						"failed to verify on packet %u @0x%x: ",
						fu_chunk_get_idx (chk), fu_chunk_get_address (chk));
				return FALSE;
			}
		}
		if (operation == FU_LENOVO_DOCK_OPERATION_READ) {
			if (!fu_memcpy_safe (fu_chunk_get_data_out (chk),
					     fu_chunk_get_data_sz (chk), 0x0, /* dst */
					     inbuf, sizeof(inbuf), idx_read, /* src */
					     fu_chunk_get_data_sz (chk), error))
				return FALSE;
		}
	}

	/* success */
	return TRUE;
}

static gboolean
fu_lenovo_dock_device_register_clear_bit (FuLenovoDockDevice *self,
						guint32 address,
						guint8 bit_position,
						GError **error)
{
	guint8 tmp = 0x0;
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						    address, &tmp, sizeof(tmp),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error))
		return FALSE;
	tmp &= ~(1 << bit_position);
	return fu_lenovo_dock_device_operation (self,
						      FU_LENOVO_DOCK_OPERATION_WRITE,
						      FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						      address,
						      &tmp, sizeof(guint8),
						      FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						      error);
}

static gboolean
fu_lenovo_dock_device_register_set_bit (FuLenovoDockDevice *self,
					      guint32 address,
					      guint8 bit_position,
					      GError **error)
{
	guint8 tmp = 0x0;
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						    address, &tmp, sizeof(tmp),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error))
		return FALSE;
	tmp |= 1 << bit_position;
	return fu_lenovo_dock_device_operation (self,
						      FU_LENOVO_DOCK_OPERATION_WRITE,
						      FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						      address, &tmp, sizeof(tmp),
						      FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						      error);
}

static gchar *
fu_lenovo_dock_device_eeprom_read_string (FuLenovoDockDevice *self,
						guint32 address,
						GError **error)
{
	FuLenovoDockEepromStringHeader header = { 0 };
	g_autofree gchar *str = NULL;

	/* read header */
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    address,
						    (guint8 *) &header, sizeof(header),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error,
				"failed to read EEPROM string header @0x%x: ",
				address);
		return NULL;
	}

	/* sanity check */
	if (header.Type != FU_LENOVO_DOCK_DEVICE_CAPABILITIES_BYTE) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "EEPROM string header type invalid");
		return NULL;
	}
	if (header.Length < sizeof(header)) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "EEPROM string header length invalid");
		return NULL;
	}

	/* allocate buffer + NUL terminator */
	str = g_malloc0 (header.Length - sizeof(header) + 1);
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    address + sizeof(header),
						    (guint8 *) str,
						    header.Length - sizeof(header),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error,
				"failed to read EEPROM string @0x%x: ",
				address);
		return NULL;
	}
	return g_steal_pointer (&str);
}

static gboolean
fu_lenovo_dock_device_ensure_patch_level (FuLenovoDockDevice *self, GError **error)
{
	guint8 tmp = 0x0;
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    self->eeprom_patch_valid_addr,
						    &tmp, sizeof(tmp),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM patch validation byte: ");
		return FALSE;
	}
	if (tmp == FU_LENOVO_DOCK_SIGNATURE_PATCH_BYTE) {
		self->patch_level = 1;
		return TRUE;
	}
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    self->eeprom_patch2_valid_addr,
						    &tmp, sizeof(tmp),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM patch validation byte: ");
		return FALSE;
	}
	if (tmp == FU_LENOVO_DOCK_SIGNATURE_PATCH_BYTE) {
		self->patch_level = 2;
		return TRUE;
	}

	/* not sure what to do here */
	g_set_error_literal (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "EEPROM patch version undiscoverable");
	return FALSE;
}

static gboolean
fu_lenovo_dock_device_setup (FuDevice *device, GError **error)
{
//USI--> test
	g_debug("USI, fu_lenovo_dock_device_setup");
        //gchar *devpath = g_strdup (fu_udev_device_get_sysfs_path (FU_UDEV_DEVICE (device)));

	gchar *contents = NULL;
	gchar *version = NULL;
	gboolean ret = g_file_get_contents ("/sys/bus/usb/drivers/usb/3-3.2/bcdDevice", &contents, NULL, NULL);

	g_auto(GStrv) lines = NULL;
	if (ret)
		lines = fu_common_strnsplit(contents, sizeof(contents), "\n", -1);

//<--USI

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	GUsbDevice *usb_device = fu_usb_device_get_dev (FU_USB_DEVICE (device));
	FuLenovoDockEepromCustomInfo cinfo = { 0x0 };
	guint32 addr = FU_LENOVO_DOCK_EEPROM_CPX_PATCH_VERSION_ADDRESS;
	guint8 chip_id_offset = 0x0;
	guint8 sigbuf[2] = { 0x0 };
	guint8 verbuf_fw[4] = { 0x0 };
	guint8 verbuf_patch[3] = { 0x0 };
	g_autofree gchar *cap_str = NULL;
	g_autofree gchar *chip_id = NULL;
	g_autofree gchar *summary = NULL;
	g_autofree gchar *version_fw = NULL;
	g_autofree gchar *version_patch = NULL;

	guint idx;
	gint rc;
	GUsbDevicePrivate *priv;
	priv = usb_device->priv;

	/* FuUsbDevice->setup */
	if (!FU_DEVICE_CLASS (fu_lenovo_dock_device_parent_class)->setup (device, error))
		return FALSE;

///USI--> test 
#if 1
        guint8 inbuf[64] = { 0 };
        guint8 outbuf[64] = {2, 4, 0xfe, 0xff, 1};
        outbuf[63] = 0x6a;

        if (!fu_lenovo_dock_device_output_report (self, outbuf, sizeof(outbuf), error))
                                return FALSE;
        if (!fu_lenovo_dock_device_input_report (self,
                                                               FU_LENOVO_DOCK_MEM_READID,
                                                               inbuf, sizeof(inbuf),
                                                               error))
                                return FALSE;
#endif
//<--USI
	if (ret)
		fu_device_set_version (device, lines[0]);
	else fu_device_set_version (device, "0017");

//	self->chip_id = self->chip_id_base + chip_id_offset;
//	chip_id = g_strdup_printf ("lenovo_dock\\CX%u", self->chip_id);
	chip_id = g_strdup_printf ("lenovo_dock\\TBT4");	
	fu_device_add_instance_id (device, chip_id);

	/* set summary */
//	summary = g_strdup_printf ("CX%u USB audio device", self->chip_id);
//	fu_device_set_summary (device, summary);
	fu_device_set_summary (device, "Lenovo Dock MCU Controller");
	return TRUE;

	/* read the EEPROM validity signature */
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    FU_LENOVO_DOCK_EEPROM_VALIDITY_SIGNATURE_OFFSET,
						    sigbuf, sizeof(sigbuf),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM signature bytes: ");
		return FALSE;
	}

	/* blank EEPROM */
	if (sigbuf[0] == 0xff && sigbuf[1] == 0xff) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "EEPROM is missing or blank");
		return FALSE;
	}

	/* is disabled on EVK board using jumper */
	if ((sigbuf[0] == 0x00 && sigbuf[1] == 0x00) ||
	    (sigbuf[0] == 0xff && sigbuf[1] == 0x00)) {
		g_set_error_literal (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "EEPROM has been disabled using a jumper");
		return FALSE;
	}

	/* check magic byte */
	if (sigbuf[0] != FU_LENOVO_DOCK_MAGIC_BYTE) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "EEPROM magic byte invalid, got 0x%02x expected 0x%02x",
			     sigbuf[0], (guint) FU_LENOVO_DOCK_MAGIC_BYTE);
		return FALSE;
	}

	/* calculate EEPROM size */
	self->eeprom_sz = (guint32) 1 << (sigbuf[1] + 8);
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    FU_LENOVO_DOCK_EEPROM_STORAGE_SIZE_ADDRESS,
						    sigbuf, sizeof(sigbuf),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM signature bytes: ");
		return FALSE;
	}
	self->eeprom_storage_sz = fu_common_read_uint16 (sigbuf, G_LITTLE_ENDIAN);
	if (self->eeprom_storage_sz < self->eeprom_sz - FU_LENOVO_DOCK_EEPROM_STORAGE_PADDING_SIZE) {
		self->eeprom_storage_address = self->eeprom_sz - \
						self->eeprom_storage_sz - \
						FU_LENOVO_DOCK_EEPROM_STORAGE_PADDING_SIZE;
	}

	/* get EEPROM custom info */
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    FU_LENOVO_DOCK_EEPROM_CUSTOM_INFO_OFFSET,
						    (guint8 *) &cinfo, sizeof(cinfo),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM custom info: ");
		return FALSE;
	}
	if (cinfo.LayoutSignature == FU_LENOVO_DOCK_SIGNATURE_BYTE)
		self->eeprom_layout_version = cinfo.LayoutVersion;
	g_debug ("CpxPatchVersion: %u.%u.%u",
		 cinfo.CpxPatchVersion[0],
		 cinfo.CpxPatchVersion[1],
		 cinfo.CpxPatchVersion[2]);
	g_debug ("SpxPatchVersion: %u.%u.%u.%u",
		 cinfo.SpxPatchVersion[0],
		 cinfo.SpxPatchVersion[1],
		 cinfo.SpxPatchVersion[2],
		 cinfo.SpxPatchVersion[3]);
	g_debug ("VendorID: 0x%04x", cinfo.VendorID);
	g_debug ("ProductID: 0x%04x", cinfo.ProductID);
	g_debug ("RevisionID: 0x%04x", cinfo.RevisionID);
	g_debug ("ApplicationStatus: 0x%02x", cinfo.ApplicationStatus);

	/* serial number, which also allows us to recover it after write */
	if (self->eeprom_layout_version >= 0x01) {
		self->serial_number_set = cinfo.SerialNumberStringAddress != 0x0;
		if (self->serial_number_set) {
			g_autofree gchar *tmp = NULL;
			tmp = fu_lenovo_dock_device_eeprom_read_string (self,
									      cinfo.SerialNumberStringAddress,
									      error);
			if (tmp == NULL)
				return FALSE;
			fu_device_set_serial (device, tmp);
		}
	}

	/* read fw version */
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						    FU_LENOVO_DOCK_REG_FIRMWARE_VERSION_ADDR,
						    verbuf_fw, sizeof(verbuf_fw),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM firmware version: ");
		return FALSE;
	}
	version_fw = g_strdup_printf ("%02X.%02X.%02X.%02X",
				      verbuf_fw[1], verbuf_fw[0],
				      verbuf_fw[3], verbuf_fw[2]);
	fu_device_set_version_bootloader (device, version_fw);

	/* use a different address if a patch is in use */
	if (self->eeprom_patch_valid_addr != 0x0) {
		if (!fu_lenovo_dock_device_ensure_patch_level (self, error))
			return FALSE;
	}
	if (self->patch_level == 2)
		addr = FU_LENOVO_DOCK_EEPROM_CPX_PATCH2_VERSION_ADDRESS;
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_READ,
						    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
						    addr, verbuf_patch, sizeof(verbuf_patch),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		g_prefix_error (error, "failed to read EEPROM patch version: ");
		return FALSE;
	}
	version_patch = g_strdup_printf ("%02X-%02X-%02X",
					 verbuf_patch[0], verbuf_patch[1], verbuf_patch[2]);
	fu_device_set_version (device, version_patch);

	/* find out if patch supports additional capabilities (optional) */
	cap_str = g_usb_device_get_string_descriptor (usb_device,
						      FU_LENOVO_DOCK_DEVICE_CAPABILITIES_STRIDX,
						      NULL);
	if (cap_str != NULL) {
		g_auto(GStrv) split = g_strsplit (cap_str, ";", -1);
		for (guint i = 0; split[i] != NULL; i++) {
			g_debug ("capability: %s", split[i]);
			if (g_strcmp0 (split[i], "RESET") == 0)
				self->sw_reset_supported = TRUE;
		}
	}

	/* success */
	return TRUE;
}

static FuFirmware *
fu_lenovo_dock_device_prepare_firmware (FuDevice *device,
					      GBytes *fw,
					      FwupdInstallFlags flags,
					      GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_prepare_firmware");

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	guint32 chip_id_base;
	g_autoptr(FuFirmware) firmware = fu_lenovo_dock_firmware_new ();
	if (!fu_firmware_parse (firmware, fw, flags, error))
		return NULL;
	chip_id_base = fu_lenovo_dock_firmware_get_devtype (FU_LENOVO_DOCK_FIRMWARE (firmware));
	if (chip_id_base != self->chip_id_base) {
		g_set_error (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_INVALID_FILE,
			     "device 0x%04u is incompatible with firmware 0x%04u",
			     self->chip_id_base, chip_id_base);
		return NULL;
	}
	return g_steal_pointer (&firmware);
}

static gboolean
fu_lenovo_dock_device_write_firmware (FuDevice *device,
					    FuFirmware *firmware,
					    FwupdInstallFlags flags,
					    GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_write_firmware");
	return TRUE;

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	GPtrArray *records = fu_srec_firmware_get_records (FU_SREC_FIRMWARE (firmware));
	FuLenovoDockFileKind file_kind;

	/* check if a patch file fits completely into the EEPROM */
	for (guint i = 0; i < records->len; i++) {
		FuSrecFirmwareRecord *rcd = g_ptr_array_index (records, i);
		if (rcd->kind == FU_FIRMWARE_SREC_RECORD_KIND_S9_TERMINATION_16)
			continue;
		if (rcd->kind == FU_FIRMWARE_SREC_RECORD_KIND_LAST)
			continue;
		if (rcd->addr > self->eeprom_sz) {
			g_set_error (error,
				     FWUPD_ERROR,
				     FWUPD_ERROR_NOT_SUPPORTED,
				     "EEPROM address 0x%02x is bigger than size 0x%02x",
				     rcd->addr, self->eeprom_sz);
			return FALSE;
		}
	}

	/* park the FW: run only the basic functionality until the upgrade is over */
	if (!fu_lenovo_dock_device_register_set_bit (self, FU_LENOVO_DOCK_REG_FIRMWARE_PARK_ADDR, 7, error))
		return FALSE;
	g_usleep (10 * 1000);

	/* initialize layout signature and version to 0 if transitioning from
	 * EEPROM layout version 1 => 0 */
	file_kind = fu_lenovo_dock_firmware_get_file_type (FU_LENOVO_DOCK_FIRMWARE (firmware));
	if (file_kind == FU_LENOVO_DOCK_FILE_KIND_CX2070X_FW &&
	    self->eeprom_layout_version >= 1 &&
	    fu_lenovo_dock_firmware_get_layout_version (FU_LENOVO_DOCK_FIRMWARE (firmware)) == 0) {
		guint8 value = 0;
		if (!fu_lenovo_dock_device_operation (self,
							    FU_LENOVO_DOCK_OPERATION_WRITE,
							    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
							    FU_LENOVO_DOCK_EEPROM_LAYOUT_SIGNATURE_ADDRESS,
							    &value, sizeof(value),
							    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
							    error)) {
			g_prefix_error (error, "failed to initialize layout signature: ");
			return FALSE;
		}
		if (!fu_lenovo_dock_device_operation (self,
							    FU_LENOVO_DOCK_OPERATION_WRITE,
							    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
							    FU_LENOVO_DOCK_EEPROM_LAYOUT_VERSION_ADDRESS,
							    &value, sizeof(value),
							    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
							    error)) {
			g_prefix_error (error, "failed to initialize layout signature: ");
			return FALSE;
		}
		g_debug ("initialized layout signature");
	}

	/* perform the actual write */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_WRITE);
	for (guint i = 0; i < records->len; i++) {
		FuSrecFirmwareRecord *rcd = g_ptr_array_index (records, i);
		if (rcd->kind != FU_FIRMWARE_SREC_RECORD_KIND_S3_DATA_32)
			continue;
		g_debug ("writing @0x%04x len:0x%02x", rcd->addr, rcd->buf->len);
		if (!fu_lenovo_dock_device_operation (self,
							    FU_LENOVO_DOCK_OPERATION_WRITE,
							    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
							    rcd->addr,
							    rcd->buf->data, rcd->buf->len,
							    FU_LENOVO_DOCK_OPERATION_FLAG_VERIFY,
							    error)) {
			g_prefix_error (error, "failed to write @0x%04x len:0x%02x: ",
					rcd->addr, rcd->buf->len);
			return FALSE;
		}
		fu_device_set_progress_full (device, (gsize) i, (gsize) records->len);
	}

	/* in case of a full FW upgrade invalidate the old FW patch (if any)
	 * as it may have not been done by the S37 file */
	if (file_kind == FU_LENOVO_DOCK_FILE_KIND_CX2070X_FW) {
		FuLenovoDockEepromPatchInfo pinfo = { 0 };
		if (!fu_lenovo_dock_device_operation (self,
							    FU_LENOVO_DOCK_OPERATION_READ,
							    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
							    FU_LENOVO_DOCK_EEPROM_PATCH_INFO_OFFSET,
							    (guint8 *) &pinfo, sizeof(pinfo),
							    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
							    error)) {
			g_prefix_error (error, "failed to read EEPROM patch info: ");
			return FALSE;
		}
		if (pinfo.PatchSignature == FU_LENOVO_DOCK_SIGNATURE_PATCH_BYTE) {
			memset (&pinfo, 0x0, sizeof(pinfo));
			if (!fu_lenovo_dock_device_operation (self,
								    FU_LENOVO_DOCK_OPERATION_WRITE,
								    FU_LENOVO_DOCK_MEM_KIND_EEPROM,
								    FU_LENOVO_DOCK_EEPROM_PATCH_INFO_OFFSET,
								    (guint8 *) &pinfo, sizeof(pinfo),
								    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
								    error)) {
				g_prefix_error (error, "failed to write empty EEPROM patch info: ");
				return FALSE;
			}
			g_debug ("invalidated old FW patch for CX2070x (RAM) device");
		}
	}

	/* unpark the FW */
	if (!fu_lenovo_dock_device_register_clear_bit (self,
							     FU_LENOVO_DOCK_REG_FIRMWARE_PARK_ADDR,
							     7, error))
		return FALSE;

	/* success */
	return TRUE;
}


static gboolean
fu_lenovo_dock_device_attach (FuDevice *device, GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_attach");
	return TRUE;

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	guint8 tmp = 1 << 6;
	g_autoptr(GError) error_local = NULL;

	/* is disabled on EVK board using jumper */
	if (!self->sw_reset_supported)
		return TRUE;

	/* wait for re-enumeration */
	fu_device_set_status (device, FWUPD_STATUS_DEVICE_RESTART);
	fu_device_add_flag (device, FWUPD_DEVICE_FLAG_WAIT_FOR_REPLUG);

	/* this fails on success */
	if (!fu_lenovo_dock_device_operation (self,
						    FU_LENOVO_DOCK_OPERATION_WRITE,
						    FU_LENOVO_DOCK_MEM_KIND_CPX_RAM,
						    FU_LENOVO_DOCK_REG_RESET_ADDR, &tmp, sizeof(tmp),
						    FU_LENOVO_DOCK_OPERATION_FLAG_NONE,
						    error)) {
		if (g_error_matches (error_local,
				     G_USB_DEVICE_ERROR,
				     G_USB_DEVICE_ERROR_FAILED)) {
			return TRUE;
		}
		g_propagate_error (error, g_steal_pointer (&error_local));
		return FALSE;
	}
	return TRUE;
}

static gboolean
fu_lenovo_dock_device_set_quirk_kv (FuDevice *device,
					const gchar *key,
					const gchar *value,
					GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_class_init");

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	if (g_strcmp0 (key, "LenovoDockOption") == 0) {
		self->lenovo_dock_option = fu_common_strtoull (value);
		return TRUE;
	}
	g_set_error_literal (error,
			     FWUPD_ERROR,
			     FWUPD_ERROR_NOT_SUPPORTED,
			     "quirk key not supported");
	return FALSE;
}

static gboolean
fu_lenovo_dock_device_prepare (FuDevice *device,
              		        	FwupdInstallFlags flags,
					GError **error)
{
	g_debug("USI, fu_lenovo_dock_device_prepare");

        //FuUefiDevice *self = FU_UEFI_DEVICE (device);
        //FuUefiDevicePrivate *priv = GET_PRIVATE (self);

        /* mount if required 
        priv->esp_locker = fu_volume_locker (priv->esp, error);
        if (priv->esp_locker == NULL)
                return FALSE;*/

	FuLenovoDockDevice *self = FU_LENOVO_DOCK_DEVICE (device);
	
	guint8 inbuf[FU_LENOVO_DOCK_INPUT_REPORT_SIZE] = { 0 };
	guint8 outbuf[FU_LENOVO_DOCK_OUTPUT_REPORT_SIZE] = {2, 4, 0xfe, 0xff, 13};
	outbuf[63] = 0x6a;

	if (!fu_lenovo_dock_device_output_report (self, outbuf, sizeof(outbuf), error))
                        return FALSE;

        if (!fu_lenovo_dock_device_input_report (self, FU_LENOVO_DOCK_MEM_READID,
                                                               inbuf, sizeof(inbuf),
                                                               error))
                                return FALSE;



        return TRUE;
}

static void
fu_lenovo_dock_device_init (FuLenovoDockDevice *self)
{
	g_debug("USI, fu_lenovo_dock_device_init");
	self->sw_reset_supported = TRUE;
	fu_device_add_icon (FU_DEVICE (self), "dock");
	fu_device_add_flag (FU_DEVICE (self), FWUPD_DEVICE_FLAG_UPDATABLE);
	fu_device_set_version_format (FU_DEVICE (self), FWUPD_VERSION_FORMAT_PLAIN);
	fu_device_set_install_duration (FU_DEVICE (self), 300); /* seconds */
	fu_device_add_protocol (FU_DEVICE (self), "com.lenovo.dock");
	fu_device_retry_set_delay (FU_DEVICE (self), 100); /* ms */
	fu_device_set_remove_delay (FU_DEVICE (self), FU_DEVICE_REMOVE_DELAY_RE_ENUMERATE);

	fu_device_add_internal_flag(FU_DEVICE(self), FU_DEVICE_INTERNAL_FLAG_NO_SERIAL_NUMBER);
}

static void
fu_lenovo_dock_device_class_init (FuLenovoDockDeviceClass *klass)
{
	g_debug("USI, fu_lenovo_dock_device_class_init");
	FuDeviceClass *klass_device = FU_DEVICE_CLASS (klass);
	klass_device->to_string = fu_lenovo_dock_device_to_string;
	klass_device->set_quirk_kv = fu_lenovo_dock_device_set_quirk_kv;
	klass_device->setup = fu_lenovo_dock_device_setup;
	klass_device->write_firmware = fu_lenovo_dock_device_write_firmware;
	klass_device->attach = fu_lenovo_dock_device_attach;
	klass_device->prepare_firmware = fu_lenovo_dock_device_prepare_firmware;
	klass_device->prepare = fu_lenovo_dock_device_prepare;
}
