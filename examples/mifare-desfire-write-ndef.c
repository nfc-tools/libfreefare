/*-
 * Copyright (C) 2010, Audrey Diacre.
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
#include <stdlib.h>

#include <freefare.h>

/*
 * This example was written based on information provided by the
 * following documents:
 *
 * Mifare DESFire as Type 4 Tag
 * NFC Forum Type 4 Tag Extensions for Mifare DESFire
 * Rev. 1.1 - 21 August 2007
 *
 */


uint8_t key_data_app[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// TODO: allow NDEF payload to be provided e.g. via an external file
const uint8_t ndef_msg[35] = {
    0x00, 0x21,
    0xd1, 0x02, 0x1c, 0x53, 0x70, 0x91, 0x01, 0x09,
    0x54, 0x02, 0x65, 0x6e, 0x4c, 0x69, 0x62, 0x6e,
    0x66, 0x63, 0x51, 0x01, 0x0b, 0x55, 0x03, 0x6c,
    0x69, 0x62, 0x6e, 0x66, 0x63, 0x2e, 0x6f, 0x72,
    0x67
};

int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    MifareTag *tags = NULL;

    printf ("NOTE: This application writes a NDEF payload into a Mifare DESFire formatted as NFC Forum Type 4 Tag.\n");

    if (argc > 1)
	errx (EXIT_FAILURE, "usage: %s", argv[0]);

    nfc_connstring devices[8];
    size_t device_count;
    
    nfc_init(NULL);

    device_count = nfc_list_devices (NULL, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
        device = nfc_open (NULL, devices[d]);
        
        if (!device) {
            warnx ("nfc_open() failed.");
            error = EXIT_FAILURE;
            continue;
        }

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    if (DESFIRE != freefare_get_tag_type (tags[i]))
		continue;

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    char buffer[BUFSIZ];

	    printf ("Found %s with UID %s.  Write NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    fgets (buffer, BUFSIZ, stdin);
	    bool write_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	    if (write_ndef) {
		int res;

		res = mifare_desfire_connect (tags[i]);
		if (res < 0) {
		    warnx ("Can't connect to Mifare DESFire target.");
		    error = EXIT_FAILURE;
		    break;
		}

		MifareDESFireKey key_app;
		key_app  = mifare_desfire_des_key_new_with_version (key_data_app);

		// Mifare DESFire SelectApplication (Select application)
		MifareDESFireAID aid = mifare_desfire_aid_new(0xEEEE10);
		res = mifare_desfire_select_application(tags[i], aid);
		if (res < 0)
		    errx (EXIT_FAILURE, "Application selection failed. Try mifare-desfire-format-ndef before running %s.", argv[0]);
		free (aid);

		// Authentication with NDEF Tag Application master key (Authentication with key 0)
		res = mifare_desfire_authenticate (tags[i], 0, key_app);
		if (res < 0)
		    errx (EXIT_FAILURE, "Authentication with NDEF Tag Application master key failed");

// TODO: read and check Capability Container
// Steps not implemented at this stage:
// Read and parse CC (E103)
// - Read NDEF file pointer (can be != E104)
// - Check available space for storing NDEF
// - Check is writing is allowed and propose to overrule it if needed

		//Mifare DESFire WriteData to write the content of the NDEF File with NLEN equal to NDEF Message length and NDEF Message
		res = mifare_desfire_write_data(tags[i], 0x04, 0, sizeof(ndef_msg), (uint8_t *) ndef_msg);
		if (res < 0)
		    errx (EXIT_FAILURE, " Write data failed");

		mifare_desfire_key_free (key_app);

		mifare_desfire_disconnect (tags[i]);
	    }
	    free (tag_uid);
	}
	freefare_free_tags (tags);
	nfc_close (device);
    }
    nfc_exit(NULL);
    exit (error);
}
