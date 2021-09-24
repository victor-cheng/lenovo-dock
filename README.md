# Dock MCU controller

## Introduction

This plugin is used to update a small subset of Conexant (now owned by Lenovo-USI)
Dock MCU devices.

## Firmware Format

The daemon will decompress the cabinet archive and extract a firmware blob in
a modified SREC file format.

This plugin supports the following protocol ID:

* com.lenovo.dock

## GUID Generation

These devices use the standard USB DeviceInstanceId values, e.g.

* `USB\VID_17EF&PID_30B4&REV_0100`
* `USB\VID_17EF&PID_30B4`

These devices also use custom GUID values, e.g.

* `LENOVO_DOCK\TBT4`

## Update Behavior

The firmware is deployed when the device is in normal runtime mode, and the
device will reset when the new firmware has been written.

## Quirk Use

This plugin uses the following plugin-specific quirks:

### LenovoDockOption

Options.

## External Interface Access

This plugin requires read/write access to `/dev/bus/usb`.
