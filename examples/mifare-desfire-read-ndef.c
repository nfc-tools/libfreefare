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

#include "config.h"

#include <err.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

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

// Note that it is using specific Desfire commands, not ISO7816 NDEF Tag Type4 commands

uint8_t key_data_app[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

uint8_t *cc_data;
uint8_t *ndef_msg;
uint16_t  ndef_msg_len;

struct {
    bool interactive;
} read_options = {
    .interactive = true
};

void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-y] -o FILE [-k 11223344AABBCCDD]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation\n");
    fprintf (stderr, "  -o     Extract NDEF message if available in FILE\n");
    fprintf (stderr, "  -k     Provide another NDEF Tag Application key than the default one\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    MifareTag *tags = NULL;

    char *ndef_output = NULL;
    while ((ch = getopt (argc, argv, "hyo:k:")) != -1) {
        switch (ch) {
        case 'h':
            usage(argv[0]);
            exit (EXIT_SUCCESS);
            break;
        case 'y':
            read_options.interactive = false;
            break;
        case 'o':
            ndef_output = optarg;
            break;
        case 'k':
            if (strlen(optarg) != 16) {
                usage(argv[0]);
                exit (EXIT_FAILURE);
            }
            uint64_t n = strtoull(optarg, NULL, 16);
            int i;
            for (i=7; i>=0; i--) {
                key_data_app[i] = (uint8_t) n;
                n >>= 8;
            }
            break;
        default:
            usage(argv[0]);
            exit (EXIT_FAILURE);
        }
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    printf ("NOTE: This application reads a NDEF payload from a Mifare DESFire formatted as NFC Forum Type 4 Tag.\n");

    if (ndef_output == NULL) {
	usage (argv[0]);
	exit (EXIT_FAILURE);
    }
    FILE* message_stream = NULL;
    FILE* ndef_stream = NULL;

    if ((strlen (ndef_output) == 1) && (ndef_output[0] == '-')) {
	message_stream = stderr;
	ndef_stream = stdout;
    } else {
	message_stream = stdout;
	ndef_stream = fopen(ndef_output, "wb");
	if (!ndef_stream) {
	    fprintf (stderr, "Could not open file %s.\n", ndef_output);
	    exit (EXIT_FAILURE);
	}
    }

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

	    fprintf (message_stream, "Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);

	    bool read_ndef = true;
	    if (read_options.interactive) {
		printf ("Read NDEF [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		read_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (read_ndef) {
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
		    errx (EXIT_FAILURE, "Application selection failed. Try mifare-desfire-create-ndef before running %s.", argv[0]);
		free (aid);

		// Authentication with NDEF Tag Application master key (Authentication with key 0)
		res = mifare_desfire_authenticate (tags[i], 0, key_app);
		if (res < 0)
		    errx (EXIT_FAILURE, "Authentication with NDEF Tag Application master key failed");

		// Read Capability Container file E103
		uint8_t lendata[2];
		res = mifare_desfire_read_data (tags[i], 0x03, 0, 2, lendata);
		if (res < 0)
		    errx (EXIT_FAILURE, "Read CC len failed");
		uint16_t cclen = (((uint16_t) lendata[0]) << 8) + ((uint16_t) lendata[1]);
		if (cclen < 15)
		    errx (EXIT_FAILURE, "CC too short IMHO");
		if (!(cc_data = malloc(cclen)))
		    errx (EXIT_FAILURE, "malloc");
		res = mifare_desfire_read_data (tags[i], 0x03, 0, cclen, cc_data);
		if (res < 0)
		    errx (EXIT_FAILURE, "Read CC data failed");
		// Search NDEF File Control TLV
		uint8_t off = 7;
		while (((off+7) < cclen) && (cc_data[off] != 0x04)) {
		    // Skip TLV
		    off += cc_data[off+1] + 2;
		}
		if (off+7 >= cclen)
		    errx (EXIT_FAILURE, "CC does not contain expected NDEF File Control TLV");
		if (cc_data[off+2] != 0xE1)
		    errx (EXIT_FAILURE, "Unknown NDEF File reference in CC");
		uint8_t file_no = cc_data[off+3];
		uint16_t ndefmaxlen = (((uint16_t) cc_data[off+4]) << 8) + ((uint16_t) cc_data[off+5]);
		fprintf (message_stream, "Max NDEF size: %i bytes\n", ndefmaxlen);
		if (!(ndef_msg = malloc(ndefmaxlen)))
		    errx (EXIT_FAILURE, "malloc");

		res = mifare_desfire_read_data (tags[i], file_no, 0, 2, lendata);
		if (res < 0)
		    errx (EXIT_FAILURE, "Read NDEF len failed");
		ndef_msg_len = (((uint16_t) lendata[0]) << 8) + ((uint16_t) lendata[1]);
		fprintf (message_stream, "NDEF size: %i bytes\n", ndef_msg_len);
		if (ndef_msg_len + 2 > ndefmaxlen)
		    errx (EXIT_FAILURE, "Declared NDEF size larger than max NDEF size");
		res = mifare_desfire_read_data (tags[i], file_no, 2, ndef_msg_len, ndef_msg);
		if (res < 0)
		    errx (EXIT_FAILURE, "Read data failed");
		if (fwrite (ndef_msg, 1, ndef_msg_len, ndef_stream) != ndef_msg_len)
		    errx (EXIT_FAILURE, "Write to file failed");
		free (cc_data);
		free (ndef_msg);
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
