/*-
 * Copyright (C) 2015, Romain Tartiere.
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
 */

#include <err.h>
#include <stdlib.h>

#include <nfc/nfc.h>

#include <freefare.h>

int
main (void)
{
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    nfc_connstring devices[8];

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx (EXIT_FAILURE, "Unable to init libnfc (malloc)");

    size_t device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
	device = nfc_open (context, devices[d]);
	if (!device) {
	    errx (EXIT_FAILURE, "nfc_open() failed.");
	}

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing FeliCa tag.");
	}

	for (int i = 0; tags[i]; i++) {
	    int r = felica_connect (tags[i]);
	    if (r < 0)
		errx (EXIT_FAILURE, "Cannot connect to FeliCa target");

	    printf ("Dumping %s tag %s\n", freefare_get_tag_friendly_name (tags[i]), freefare_get_tag_uid (tags[i]));
	    printf ("Number\tName\tData\n");

	    for (int block = 0x00; block < 0x0f; block++) {
		uint8_t buffer[16];

		if (felica_read (tags[i], FELICA_SC_RO, block, buffer, sizeof (buffer)) < 0)
		    errx (EXIT_FAILURE, "Error reading block %d", block);

		if (block < 0x0e)
		    printf ("0x%02x\tS_PAD%d\t", block, block);
		else
		    printf ("0x%02x\tREG\t", block);
		for (int j = 0; j < 16; j++) {
		    printf ("%02x ", buffer[j]);
		}
		printf ("\n");
	    }

	    char *block_names[] = {
		"RC", "MAC", "ID", "D_ID", "SER_C", "SYS_C", "CKV", "CK", "MC",
	    };
	    int valid_bytes[] = {
		16, 8, 16, 16, 2, 2, 2, 16, 5
	    };
	    for (int block = 0x80; block < 0x89; block++) {
		uint8_t buffer[16];

		if (felica_read (tags[i], FELICA_SC_RO, block, buffer, sizeof (buffer)) < 0)
		    errx (EXIT_FAILURE, "Error reading block %d", block);

		printf ("0x%02x\t%s\t", block, block_names[block - 0x80]);
		for (int j = 0; j < valid_bytes[block - 0x80]; j++) {
		    printf ("%02x ", buffer[j]);
		}
		printf ("\n");
	    }

	    felica_disconnect (tags[i]);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }

    exit(EXIT_SUCCESS);
}
