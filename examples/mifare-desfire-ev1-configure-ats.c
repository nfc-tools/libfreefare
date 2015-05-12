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
 */

#include "config.h"

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t key_data_picc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

// TODO: Allow to pass another ATS as option
// Default Mifare DESFire ATS
uint8_t new_ats[] = { 0x06, 0x75, 0x77, 0x81, 0x02, 0x80 };

struct {
    bool interactive;
} configure_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-y] [-K 11223344AABBCCDD]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation (dangerous)\n");
    fprintf (stderr, "  -K     Provide another PICC key than the default one\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "hyK:")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit (EXIT_SUCCESS);
	    break;
	case 'y':
	    configure_options.interactive = false;
	    break;
	case 'K':
	    if (strlen(optarg) != 16) {
		usage(argv[0]);
		exit (EXIT_FAILURE);
	    }
	    uint64_t n = strtoull(optarg, NULL, 16);
	    int i;
	    for (i=7; i>=0; i--) {
		key_data_picc[i] = (uint8_t) n;
		n >>= 8;
	    }
	    break;
	default:
	    usage(argv[0]);
	    exit (EXIT_FAILURE);
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; (!error) && (d < device_count); d++) {
        device = nfc_open (context, devices[d]);
        if (!device) {
            warnx ("nfc_open() failed.");
            error = EXIT_FAILURE;
            continue;
        }

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing Mifare DESFire tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    if (MIFARE_DESFIRE != freefare_get_tag_type (tags[i]))
		continue;

	    char *tag_uid = freefare_get_tag_uid (tags[i]);
	    char buffer[BUFSIZ];
	    int res;

	    res = mifare_desfire_connect (tags[i]);
	    if (res < 0) {
		warnx ("Can't connect to Mifare DESFire target.");
		error = EXIT_FAILURE;
		break;
	    }

	    // Make sure we've at least an EV1 version
	    struct mifare_desfire_version_info info;
	    res = mifare_desfire_get_version (tags[i], &info);
	    if (res < 0) {
		freefare_perror (tags[i], "mifare_desfire_get_version");
		error = 1;
		break;
	    }
	    if (info.software.version_major < 1) {
		warnx ("Found old DESFire, skipping");
		continue;
	    }
	    printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    bool do_it = true;

	    if (configure_options.interactive) {
		printf ("Change ATS? [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		do_it = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (do_it) {

		MifareDESFireKey key_picc = mifare_desfire_des_key_new_with_version (key_data_picc);
		res = mifare_desfire_authenticate (tags[i], 0, key_picc);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}
		mifare_desfire_key_free (key_picc);

		res = mifare_desfire_set_ats (tags[i], new_ats);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_set_ats");
		    error = EXIT_FAILURE;
		    break;
		}

	    }

	    mifare_desfire_disconnect (tags[i]);
	    free (tag_uid);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }
    nfc_exit (context);
    exit (error);
} /* main() */

