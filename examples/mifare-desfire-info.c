/*-
 * Copyright (C) 2010, Romain Tartiere.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 * 
 * $Id$
 */

#include <err.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    nfc_device_desc_t devices[8];
    size_t device_count;

    nfc_list_devices (devices, 8, &device_count);
    if (!device_count)
        errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
	device = nfc_connect (&(devices[d]));
	if (!device) {
	    warnx ("nfc_connect() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}

    tags = freefare_get_tags (device);
    if (!tags) {
        nfc_disconnect (device);
        errx (EXIT_FAILURE, "Error listing tags.");
    }

    for (int i = 0; (!error) && tags[i]; i++) {
        if (DESFIRE != freefare_get_tag_type (tags[i]))
	    continue;

	int res;
        char *tag_uid = freefare_get_tag_uid (tags[i]);

	struct mifare_desfire_version_info info;

	res = mifare_desfire_connect (tags[i]);
	if (res < 0) {
	    warnx ("Can't connect to Mifare DESFire target.");
	    error = 1;
	    break;
	}

	res = mifare_desfire_get_version (tags[i], &info);
	if (res < 0) {
	    warnx ("Can't get Mifare DESFire version information.");
	    error = 1;
	    break;
	}

	printf ("===> Version information for tag %s:\n", tag_uid);
	printf ("UID:                      0x%02x%02x%02x%02x%02x%02x%02x\n", info.uid[0], info.uid[1], info.uid[2], info.uid[3], info.uid[4], info.uid[5], info.uid[6]);
	printf ("Batch number:             0x%02x%02x%02x%02x%02x\n", info.batch_number[0], info.batch_number[1], info.batch_number[2], info.batch_number[3], info.batch_number[4]);
	printf ("Production date:          week %x, 20%02x\n", info.production_week, info.production_year);
	printf ("Hardware Information:\n");
	printf ("    Vendor ID:            0x%02x\n", info.hardware.vendor_id);
	printf ("    Type:                 0x%02x\n", info.hardware.type);
	printf ("    Subtype:              0x%02x\n", info.hardware.subtype);
	printf ("    Version:              %d.%d\n", info.hardware.version_major, info.hardware.version_minor);
	printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.hardware.storage_size, (info.hardware.storage_size & 1) ? ">" : "=", (int)pow (2, info.hardware.storage_size >> 1));
	printf ("    Protocol:             0x%02x\n", info.hardware.protocol);
	printf ("Software Information:\n");
	printf ("    Vendor ID:            0x%02x\n", info.software.vendor_id);
	printf ("    Type:                 0x%02x\n", info.software.type);
	printf ("    Subtype:              0x%02x\n", info.software.subtype);
	printf ("    Version:              %d.%d\n", info.software.version_major, info.software.version_minor);
	printf ("    Storage size:         0x%02x (%s%d bytes)\n", info.software.storage_size, (info.software.storage_size & 1) ? ">" : "=", (int)pow (2, info.software.storage_size >> 1));
	printf ("    Protocol:             0x%02x\n", info.software.protocol);

	uint8_t settings;
	uint8_t max_keys;
	res = mifare_desfire_get_key_settings (tags[i], &settings, &max_keys);
	if (res < 0) {
	    warnx ("Cant' get Mifare DESFire Master Key settings: %s", mifare_desfire_error_lookup (mifare_desfire_get_last_error (tags[i])));
	    error = 1;
	    break;
	}

	printf ("Master Key settings (0x%02x):\n", settings);
	printf ("    0x%02x configuration changeable;\n", settings & 0x08);
	printf ("    0x%02x PICC Master Key not required for create / delete;\n", settings & 0x04);
	printf ("    0x%02x Free directory list access without PICC Master Key;\n", settings & 0x02);
	printf ("    0x%02x Allow changing the Master Key;\n", settings & 0x01);

	free (tag_uid);

	mifare_desfire_disconnect (tags[i]);
    }

    freefare_free_tags (tags);
    nfc_disconnect (device);
    }

    exit (error);
} /* main() */

