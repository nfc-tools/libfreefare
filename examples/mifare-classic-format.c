/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
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
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define START_FORMAT_N	"Formatting %d sectors ["
#define DONE_FORMAT	"] done.\n"

MifareClassicKey default_keys[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};
int		 format_mifare_classic_1k (MifareTag tag);
int		 format_mifare_classic_4k (MifareTag tag);
int		 try_format_sector (MifareTag tag, MifareClassicSectorNumber sector);

static int at_block = 0;
static int mod_block = 10;

struct {
    bool fast;
    bool interactive;
} format_options = {
    .fast        = false,
    .interactive = true
};

void
display_progress ()
{
    at_block++;
    if (0 == (at_block % mod_block)) {
	printf ("%d", at_block);
	fflush (stdout);
    } else {
	printf (".");
	fflush (stdout);
    }
}

int
format_mifare_classic_1k (MifareTag tag)
{
    printf (START_FORMAT_N, 16);
    for (int sector = 0; sector < 16; sector++) {
	if (!try_format_sector (tag, sector))
	    return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
format_mifare_classic_4k (MifareTag tag)
{
    printf (START_FORMAT_N, 32 + 8);
    for (int sector = 0; sector < (32 + 8); sector++) {
	if (!try_format_sector (tag, sector))
	    return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
try_format_sector (MifareTag tag, MifareClassicSectorNumber sector)
{
    display_progress ();
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}
    }

    warnx ("No known authentication key for sector %d", sector);
    return 0;
}

void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-fy]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -f     Fast format (only erase MAD)\n");
    fprintf (stderr, "  -y     Do not ask for confirmation (dangerous)\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;

    while ((ch = getopt (argc, argv, "fhy")) != -1) {
	switch (ch) {
	    case 'f':
		format_options.fast = true;
		break;
	    case 'h':
		usage(argv[0]);
		exit (EXIT_SUCCESS);
		break;
	    case 'y':
		format_options.interactive = false;
		break;
	    default:
		usage(argv[0]);
		exit (EXIT_FAILURE);
	}
    }
    argc -= optind;
    argv += optind;

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
	    errx (EXIT_FAILURE, "Error listing Mifare Classic tag.");
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

	    printf ("Found %s with UID %s. ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    bool format = true;
	    if (format_options.interactive) {
		printf ("Format [yN] ");
		fgets (buffer, BUFSIZ, stdin);
		format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf ("\n");
	    }

	    if (format) {
		enum mifare_tag_type tt = freefare_get_tag_type (tags[i]);
		at_block = 0;

		if (format_options.fast) {
		    printf (START_FORMAT_N, (tt == CLASSIC_1K) ? 1 : 2);
		    if (!try_format_sector (tags[i], 0x00))
			break;

		    if (tt == CLASSIC_4K)
			if (!try_format_sector (tags[i], 0x10))
			    break;

		    printf (DONE_FORMAT);
		    continue;
		}
		switch (tt) {
		    case CLASSIC_1K:
			mod_block = 4;
			if (!format_mifare_classic_1k (tags[i]))
			    error = 1;
			break;
		    case CLASSIC_4K:
			mod_block = 10;
			if (!format_mifare_classic_4k (tags[i]))
			    error = 1;
			break;
		    default:
			/* Keep compiler quiet */
			break;
		}
	    }

	    free (tag_uid);
	}

	freefare_free_tags (tags);
	nfc_disconnect (device);
    }

    exit (error);
}
