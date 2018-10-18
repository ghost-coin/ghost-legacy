// Copyright (c) 2018 The Particl Core developers
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef PARTICL_USBDEVICE_USBWRAPPER_H
#define PARTICL_USBDEVICE_USBWRAPPER_H

#include <libusb-1.0/libusb.h>

#include <wchar.h>

/*
    Can't replace hidapi on osx.
    Kernel grabs all hid devices without a signed driver.
*/

namespace usb_device {

typedef struct webusb_device {
    /* Handle to the actual device. */
    libusb_device_handle *device_handle;

    /* Endpoint information */
    int input_endpoint;
    int output_endpoint;
    int input_ep_max_packet_size;

    /* The interface number of the HID */
    int interface;

    /* Indexes of Strings */
    int manufacturer_index;
    int product_index;
    int serial_index;

    struct libusb_transfer *transfer;
} webusb_device;

typedef struct webusb_device_info {
    /** Platform-specific device path */
    char *path;
    /** Device Vendor ID */
    unsigned short vendor_id;
    /** Device Product ID */
    unsigned short product_id;
    /** Serial Number */
    wchar_t *serial_number;
    /** Device Release Number in binary-coded decimal,
        also known as Device Version Number */
    unsigned short release_number;
    /** Manufacturer String */
    wchar_t *manufacturer_string;
    /** Product string */
    wchar_t *product_string;
    /** Usage Page for this Device/Interface
        (Windows/Mac only). */
    unsigned short usage_page;
    /** Usage for this Device/Interface
        (Windows/Mac only).*/
    unsigned short usage;
    /** The USB interface which this logical device
        represents. Valid on both Linux implementations
        in all cases, and valid on the Windows implementation
        only if the device contains more than one interface. */
    int interface_number;

    /** Pointer to the next device */
    struct webusb_device_info *next;
} webusb_device_info;


int webusb_init();
int webusb_exit();

webusb_device *webusb_open_path(const char *path);
void webusb_close(webusb_device *dev);

webusb_device_info *webusb_enumerate(unsigned short vendor_id, unsigned short product_id);
void webusb_free_enumeration(struct webusb_device_info *devs);

int webusb_write(webusb_device *dev, const unsigned char *data, size_t length);
int webusb_read_timeout(webusb_device *dev, unsigned char *data, size_t length, int milliseconds);

} // usb_device

#endif // PARTICL_USBDEVICE_USBWRAPPER_H
