/*-
 * Copyright (C) 2011, Romain Tartiere, Romuald Conty.
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
 * $Id $
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * Mifare Std as NFC Forum Enabled,
 * Extensions for Mifare standard 1k/4k as NFC Forum Enable Tag
 *   Application note
 *   Revision 1.1 — 21 August 2007
 *
 * NXP Type MF1K/4K Tag Operation, NXP Semiconductors [ANNFC1K4K]
 *   Application Note
 *   Revision 1.1 — 21 August 2007
 *   Document Identifier 130410
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define MIN(a,b) ((a < b) ? a: b)

void
usage(char *progname)
{
    fprintf (stderr, "usage: %s -o FILE\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -o     Extract NDEF message if available in FILE\n");
}

int
main(int argc, char *argv[])
{
    int error = 0;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;
    Mad mad;

    int ch;
    char *ndef_output = NULL;
    while ((ch = getopt (argc, argv, "ho:")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit (EXIT_SUCCESS);
	    break;
        case 'o':
	    ndef_output = optarg;
	    break;
	case '?':
	    if (optopt == 'o')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	default:
	    usage (argv[0]);
	    exit (EXIT_FAILURE);
	}
    }

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
	    errx (EXIT_FAILURE, "Error listing MIFARE classic tag.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    switch (freefare_get_tag_type (tags[i])) {
	    case CLASSIC_1K:
	    case CLASSIC_4K:
		break;
	    default:
		continue;
	    }

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    char buffer[BUFSIZ];

	    fprintf (message_stream, "Found %s with UID %s. Read NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    fgets (buffer, BUFSIZ, stdin);
	    bool read_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	    if (read_ndef) {
		// NFCForum card has a MAD, load it.
		if (0 == mifare_classic_connect (tags[i])) {
		} else {
		    nfc_perror (device, "mifare_classic_connect");
		    error = EXIT_FAILURE;
		    goto error;
		}

		if ((mad = mad_read (tags[i]))) {
		    // Dump the NFCForum application using MAD information
		    uint8_t buffer[4096];
		    ssize_t len;
		    if ((len = mifare_application_read (tags[i], mad, mad_nfcforum_aid, buffer, sizeof(buffer), mifare_classic_nfcforum_public_key_a, MFC_KEY_A)) != -1) {
			uint8_t tlv_type;
			uint16_t tlv_data_len;
			
			uint8_t * tlv_data = tlv_decode (buffer, &tlv_type, &tlv_data_len);
			switch (tlv_type) {
			    case 0x00:
				fprintf (stderr, "NFCForum application contains a \"NULL TLV\".\n");	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
				error = EXIT_FAILURE;
				goto error;
				break;
			    case 0x03:
				fprintf (message_stream, "NFCForum application contains a \"NDEF Message TLV\".\n");
				break;
			    case 0xFD:
				fprintf (stderr, "NFCForum application contains a \"Proprietary TLV\".\n");	// FIXME: According to [ANNFC1K4K], we should skip this TLV to read further TLV blocks.
				error = EXIT_FAILURE;
				goto error;
				break;
			    case 0xFE:
				fprintf (stderr, "NFCForum application contains a \"Terminator TLV\", no available data.\n");
				error = EXIT_FAILURE;
				goto error;
				break;
			    default:
				fprintf (stderr, "NFCForum application contains an invalid TLV.\n");
				error = EXIT_FAILURE;
				goto error;
				break;
			}
			if (fwrite (tlv_data, 1, tlv_data_len, ndef_stream) != tlv_data_len) {
			    fprintf (stderr, "Could not write to file.\n");
			    error = EXIT_FAILURE;
			    goto error;
			}
			free (tlv_data);
		    } else {
			fprintf (stderr, "No NFC Forum application.\n");
			error = EXIT_FAILURE;
			goto error;
		    }
		} else {
		    fprintf (stderr, "No MAD detected.\n");
		    error = EXIT_FAILURE;
		    goto error;
		}
		free (mad);
	    }

error:
	    free (tag_uid);
	}
    fclose (ndef_stream);
	freefare_free_tags (tags);
	nfc_disconnect (device);
    }

    exit (error);
}
