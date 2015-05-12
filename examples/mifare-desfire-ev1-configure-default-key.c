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

uint8_t null_key_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t new_key_data[8]  = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

#define NEW_KEY_VERSION 0x34

struct {
    bool interactive;
} configure_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-y]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -y     Do not ask for confirmation\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "hy")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit (EXIT_SUCCESS);
	    break;
	case 'y':
	    configure_options.interactive = false;
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
		printf ("Change default key? [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		do_it = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (do_it) {

		MifareDESFireKey default_key = mifare_desfire_des_key_new_with_version (null_key_data);
		res = mifare_desfire_authenticate (tags[i], 0, default_key);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}
		mifare_desfire_key_free (default_key);

		MifareDESFireKey new_key = mifare_desfire_des_key_new (new_key_data);
		mifare_desfire_key_set_version (new_key, NEW_KEY_VERSION);
		res = mifare_desfire_set_default_key (tags[i], new_key);
		free (new_key);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_set_default_key");
		    error = EXIT_FAILURE;
		    break;
		}

		/*
		 * Perform some tests to ensure the function actually worked
		 * (it's hard to create a unit-test to do so).
		 */

		MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);
		res = mifare_desfire_create_application (tags[i], aid, 0xFF, 1);

		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_create_application");
		    error = EXIT_FAILURE;
		    break;
		}

		res = mifare_desfire_select_application (tags[i], aid);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_select_application");
		    error = EXIT_FAILURE;
		    break;
		}

		uint8_t version;
		res = mifare_desfire_get_key_version (tags[i], 0, &version);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_get_key_version");
		    error = EXIT_FAILURE;
		    break;
		}

		if (version != NEW_KEY_VERSION) {
		    fprintf (stderr, "Wrong key version: %02x (expected %02x).\n", version, NEW_KEY_VERSION);
		    error = EXIT_FAILURE;
		    /* continue */
		}

		new_key = mifare_desfire_des_key_new (new_key_data);
		res = mifare_desfire_authenticate (tags[i], 0, new_key);
		free (new_key);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}

		free (aid);

		/* Resetdefault settings */

		res = mifare_desfire_select_application (tags[i], NULL);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_select_application");
		    error = EXIT_FAILURE;
		    break;
		}

		default_key = mifare_desfire_des_key_new (null_key_data);

		res = mifare_desfire_authenticate (tags[i], 0, default_key);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}

		res = mifare_desfire_set_default_key (tags[i], default_key);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_set_default_key");
		    error = EXIT_FAILURE;
		    break;
		}

		mifare_desfire_key_free (default_key);

		/* Wipeout the card */

		res = mifare_desfire_format_picc (tags[i]);
		if (res < 0) {
		    freefare_perror (tags[i], "mifare_desfire_format_picc");
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
}
