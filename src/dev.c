// SPDX-License-Identifier: BSD-3-Clause
/* USB register access for the RTL8814AU. Vendor request protocol per rtw88 usb.c. */
#include <stdio.h>
#include <string.h>
#include "rtl8814au.h"

#define RTW_USB_CMD_READ	0xC0
#define RTW_USB_CMD_WRITE	0x40
#define RTW_USB_CMD_REQ		0x05
#define CTRL_TIMEOUT_MS		500

int rtl_open(struct rtw_dev *d, u16 vid, u16 pid)
{
	int rc;

	memset(d, 0, sizeof(*d));
	rc = libusb_init(&d->ctx);
	if (rc)
		return rc;

	d->h = libusb_open_device_with_vid_pid(d->ctx, vid, pid);
	if (!d->h) {
		libusb_exit(d->ctx);
		return LIBUSB_ERROR_NO_DEVICE;
	}
	d->usb_speed = libusb_get_device_speed(libusb_get_device(d->h));

	{
		struct libusb_config_descriptor *cfg;

		if (!libusb_get_active_config_descriptor(libusb_get_device(d->h), &cfg)) {
			const struct libusb_interface_descriptor *id = &cfg->interface[0].altsetting[0];

			for (int i = 0; i < id->bNumEndpoints; i++) {
				const struct libusb_endpoint_descriptor *e = &id->endpoint[i];

				if ((e->bmAttributes & 3) == LIBUSB_TRANSFER_TYPE_BULK &&
				    !(e->bEndpointAddress & LIBUSB_ENDPOINT_IN) && d->num_out_ep < 4)
					d->out_ep[d->num_out_ep++] = e->bEndpointAddress;
			}
			libusb_free_config_descriptor(cfg);
		}
	}

	rc = libusb_claim_interface(d->h, 0);
	if (rc) {
		libusb_close(d->h);
		libusb_exit(d->ctx);
		return rc;
	}
	return 0;
}

void rtl_close(struct rtw_dev *d)
{
	if (d->h) {
		libusb_release_interface(d->h, 0);
		libusb_close(d->h);
	}
	if (d->ctx)
		libusb_exit(d->ctx);
	memset(d, 0, sizeof(*d));
}

int rtw_debug;

static u32 rd(struct rtw_dev *d, u32 addr, u16 len)
{
	u8 buf[4] = {0};
	int n = libusb_control_transfer(d->h, RTW_USB_CMD_READ, RTW_USB_CMD_REQ,
					addr & 0xffff, 0, buf, len, CTRL_TIMEOUT_MS);

	if (n != len) {
		fprintf(stderr, "read 0x%04x len %u failed: %s\n", addr, len,
			n < 0 ? libusb_strerror(n) : "short");
		return 0xffffffffu >> (8 * (4 - len));
	}
	return buf[0] | buf[1] << 8 | buf[2] << 16 | (u32)buf[3] << 24;
}

static int wr(struct rtw_dev *d, u32 addr, u32 val, u16 len)
{
	u8 buf[4] = { val, val >> 8, val >> 16, val >> 24 };
	int n = libusb_control_transfer(d->h, RTW_USB_CMD_WRITE, RTW_USB_CMD_REQ,
					addr & 0xffff, 0, buf, len, CTRL_TIMEOUT_MS);

	if (n != len) {
		fprintf(stderr, "write 0x%04x len %u failed: %s\n", addr, len,
			n < 0 ? libusb_strerror(n) : "short");
		return -1;
	}
	return 0;
}

u8 rtw_read8(struct rtw_dev *d, u32 a)   { return rd(d, a, 1); }
u16 rtw_read16(struct rtw_dev *d, u32 a) { return rd(d, a, 2); }
u32 rtw_read32(struct rtw_dev *d, u32 a) { return rd(d, a, 4); }
void rtw_write8(struct rtw_dev *d, u32 a, u8 v)   { wr(d, a, v, 1); }
void rtw_write16(struct rtw_dev *d, u32 a, u16 v) { wr(d, a, v, 2); }
void rtw_write32(struct rtw_dev *d, u32 a, u32 v) { wr(d, a, v, 4); }


/* Block write used for firmware pages: control transfer with arbitrary length. */
int rtl_write_block(struct rtw_dev *d, u32 addr, const void *buf, u16 len)
{
	u8 tmp[512];
	int n;

	if (len > sizeof(tmp))
		return -1;
	memcpy(tmp, buf, len);
	n = libusb_control_transfer(d->h, RTW_USB_CMD_WRITE, RTW_USB_CMD_REQ,
				    addr & 0xffff, 0, tmp, len, CTRL_TIMEOUT_MS);
	return n == len ? 0 : -1;
}

int rtl_bulk_out(struct rtw_dev *d, int ep_idx, const void *buf, int len, int timeout_ms)
{
	int transferred = 0;
	int rc;

	if (ep_idx < 0 || ep_idx >= d->num_out_ep)
		return -EINVAL;
	rc = libusb_bulk_transfer(d->h, d->out_ep[ep_idx], (unsigned char *)buf, len, &transferred,
				  timeout_ms);
	if (rc || transferred != len)
		return -EIO;
	return 0;
}
