/*
 * usbprobe: first bring-up tool for the Alfa AWUS1900 (RTL8814AU, 0bda:8813).
 *
 * Finds the adapter, prints its descriptors and endpoints, tries to open and
 * claim the interface, and (with --regs) does a few read-only register reads
 * over the vendor control pipe. Writes nothing to the device.
 *
 * Usage: ./usbprobe [--vid 0bda] [--pid 8813] [--regs] [--list]
 */
#include <libusb.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DEF_VID 0x0bda
#define DEF_PID 0x8813

/* Realtek vendor request used for register access (see rtw88 usb.c). */
#define RTW_USB_CMD_REQ   0x05
#define RTW_USB_CMD_READ  0xC0 /* device-to-host | vendor | device */

static const char *speed_str(int s)
{
	switch (s) {
	case LIBUSB_SPEED_LOW: return "1.5 Mbit/s (low)";
	case LIBUSB_SPEED_FULL: return "12 Mbit/s (full)";
	case LIBUSB_SPEED_HIGH: return "480 Mbit/s (USB2)";
	case LIBUSB_SPEED_SUPER: return "5 Gbit/s (USB3)";
	case LIBUSB_SPEED_SUPER_PLUS: return "10 Gbit/s (USB3.1+)";
	default: return "unknown";
	}
}

static const char *xfer_str(uint8_t attr)
{
	switch (attr & LIBUSB_TRANSFER_TYPE_MASK) {
	case LIBUSB_TRANSFER_TYPE_CONTROL: return "control";
	case LIBUSB_TRANSFER_TYPE_ISOCHRONOUS: return "isoc";
	case LIBUSB_TRANSFER_TYPE_BULK: return "bulk";
	case LIBUSB_TRANSFER_TYPE_INTERRUPT: return "interrupt";
	}
	return "?";
}

static int read_reg(libusb_device_handle *h, uint16_t addr, void *buf, uint16_t len)
{
	return libusb_control_transfer(h, RTW_USB_CMD_READ, RTW_USB_CMD_REQ,
				       addr, 0, buf, len, 500);
}

static void list_all(libusb_context *ctx)
{
	libusb_device **list;
	ssize_t n = libusb_get_device_list(ctx, &list);

	for (ssize_t i = 0; i < n; i++) {
		struct libusb_device_descriptor d;
		if (libusb_get_device_descriptor(list[i], &d) == 0)
			printf("  %04x:%04x  bus %d addr %d\n", d.idVendor,
			       d.idProduct, libusb_get_bus_number(list[i]),
			       libusb_get_device_address(list[i]));
	}
	libusb_free_device_list(list, 1);
}

int main(int argc, char **argv)
{
	uint16_t vid = DEF_VID, pid = DEF_PID;
	int do_regs = 0, do_list = 0;

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--vid") && i + 1 < argc)
			vid = (uint16_t)strtoul(argv[++i], NULL, 16);
		else if (!strcmp(argv[i], "--pid") && i + 1 < argc)
			pid = (uint16_t)strtoul(argv[++i], NULL, 16);
		else if (!strcmp(argv[i], "--regs"))
			do_regs = 1;
		else if (!strcmp(argv[i], "--list"))
			do_list = 1;
		else {
			fprintf(stderr, "usage: %s [--vid hex] [--pid hex] [--regs] [--list]\n", argv[0]);
			return 2;
		}
	}

	libusb_context *ctx = NULL;
	int rc = libusb_init(&ctx);
	if (rc) {
		fprintf(stderr, "libusb_init: %s\n", libusb_error_name(rc));
		return 1;
	}

	if (do_list) {
		printf("USB devices seen by libusb:\n");
		list_all(ctx);
	}

	libusb_device_handle *h = libusb_open_device_with_vid_pid(ctx, vid, pid);
	if (!h) {
		fprintf(stderr, "device %04x:%04x not found or could not be opened.\n"
				"Re-run with --list to see what libusb can see.\n", vid, pid);
		libusb_exit(ctx);
		return 1;
	}

	libusb_device *dev = libusb_get_device(h);
	struct libusb_device_descriptor dd;
	libusb_get_device_descriptor(dev, &dd);

	printf("Found %04x:%04x  bcdDevice %x.%02x  bcdUSB %x.%02x\n", dd.idVendor,
	       dd.idProduct, dd.bcdDevice >> 8, dd.bcdDevice & 0xff,
	       dd.bcdUSB >> 8, dd.bcdUSB & 0xff);
	printf("Speed: %s\n", speed_str(libusb_get_device_speed(dev)));

	unsigned char s[128];
	if (dd.iManufacturer && libusb_get_string_descriptor_ascii(h, dd.iManufacturer, s, sizeof s) > 0)
		printf("Manufacturer: %s\n", s);
	if (dd.iProduct && libusb_get_string_descriptor_ascii(h, dd.iProduct, s, sizeof s) > 0)
		printf("Product: %s\n", s);

	struct libusb_config_descriptor *cfg;
	if (libusb_get_active_config_descriptor(dev, &cfg) == 0) {
		printf("Configuration %d: %d interface(s)\n", cfg->bConfigurationValue,
		       cfg->bNumInterfaces);
		for (int i = 0; i < cfg->bNumInterfaces; i++) {
			const struct libusb_interface *itf = &cfg->interface[i];
			for (int a = 0; a < itf->num_altsetting; a++) {
				const struct libusb_interface_descriptor *id = &itf->altsetting[a];
				printf("  Interface %d alt %d: class %02x/%02x/%02x, %d endpoint(s)\n",
				       id->bInterfaceNumber, id->bAlternateSetting,
				       id->bInterfaceClass, id->bInterfaceSubClass,
				       id->bInterfaceProtocol, id->bNumEndpoints);
				for (int e = 0; e < id->bNumEndpoints; e++) {
					const struct libusb_endpoint_descriptor *ep = &id->endpoint[e];
					printf("    EP 0x%02x %-3s %-9s maxpacket %u\n",
					       ep->bEndpointAddress,
					       (ep->bEndpointAddress & 0x80) ? "IN" : "OUT",
					       xfer_str(ep->bmAttributes), ep->wMaxPacketSize);
				}
			}
		}
		libusb_free_config_descriptor(cfg);
	}

	rc = libusb_claim_interface(h, 0);
	printf("Claim interface 0: %s\n", rc ? libusb_error_name(rc) : "OK");
	if (rc) {
		printf("  (if this is LIBUSB_ERROR_ACCESS/BUSY, another driver or process owns it)\n");
		libusb_close(h);
		libusb_exit(ctx);
		return 1;
	}

	if (do_regs) {
		/* Read-only. Raw values only; decoding comes in the next phase. */
		static const uint16_t regs[] = { 0x00F0, 0x00F4, 0x00FC, 0x0000 };
		for (size_t i = 0; i < sizeof regs / sizeof regs[0]; i++) {
			uint32_t v = 0;
			int n = read_reg(h, regs[i], &v, 4);
			if (n == 4)
				printf("reg 0x%04x = 0x%08x\n", regs[i], v);
			else
				printf("reg 0x%04x read failed: %s\n", regs[i],
				       n < 0 ? libusb_error_name(n) : "short read");
		}
	}

	libusb_release_interface(h, 0);
	libusb_close(h);
	libusb_exit(ctx);
	return 0;
}
