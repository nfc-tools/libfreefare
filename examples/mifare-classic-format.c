/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 * Copyright (C) 2012, Romuald Conty.
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

#if defined(HAVE_CONFIG_H)
#  include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define START_FORMAT_N	"Formatting %d sectors ["
#define DONE_FORMAT	"] done.\n"

MifareClassicKey default_keys[40];
MifareClassicKey default_keys_int[] = {
    { 0xff,0xff,0xff,0xff,0xff,0xff },
    { 0xd3,0xf7,0xd3,0xf7,0xd3,0xf7 },
    { 0xa0,0xa1,0xa2,0xa3,0xa4,0xa5 },
    { 0xb0,0xb1,0xb2,0xb3,0xb4,0xb5 },
    { 0x4d,0x3a,0x99,0xc3,0x51,0xdd },
    { 0x1a,0x98,0x2c,0x7e,0x45,0x9a },
    { 0xaa,0xbb,0xcc,0xdd,0xee,0xff },
    { 0x00,0x00,0x00,0x00,0x00,0x00 }
};
int		 format_mifare_classic_1k (FreefareTag tag);
int		 format_mifare_classic_4k (FreefareTag tag);
int		 try_format_sector (FreefareTag tag, MifareClassicSectorNumber sector);

static int at_block = 0;
static int mod_block = 10;

struct {
    bool fast;
    bool interactive;
} format_options = {
    .fast        = false,
    .interactive = true
};

static void
display_progress (void)
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
format_mifare_classic_1k (FreefareTag tag)
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
format_mifare_classic_4k (FreefareTag tag)
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
try_format_sector (FreefareTag tag, MifareClassicSectorNumber sector)
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

static void
usage(char *progname)
{
    fprintf (stderr, "usage: %s [-fy] [keyfile]\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -f      Fast format (only erase MAD)\n");
    fprintf (stderr, "  -y      Do not ask for confirmation (dangerous)\n");
    fprintf (stderr, "  keyfile Use keys from dump in addition to internal default keys\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

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
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    memcpy(default_keys, default_keys_int, sizeof(default_keys_int));

    if ((argc - optind) > 0)
    {
        int i, rc;
        char kbuffer[1024] = {0};
        memset ( kbuffer, 0, sizeof kbuffer);
        FILE *fp = fopen(argv[optind], "rb");
        if (fp == NULL)
            errx(EXIT_FAILURE, "Unable to open file");
        for (i = 0; (rc = getc(fp)) != EOF && i < 1024; kbuffer[i++] = rc) { }
        fclose(fp);

        i = sizeof(default_keys_int) / 6;
        for(int s = 0; s<16; s++)
        {
            int startblock = s * 4;
            int pos_a = (startblock + 3) * 16;
            int pos_b = (startblock + 3) * 16 + 10;
            memcpy((default_keys + i++), kbuffer + pos_a, 6);
            memcpy((default_keys + i++), kbuffer + pos_b, 6);
        }
    }

    nfc_connstring devices[8];

    size_t device_count;

    nfc_context *context;
    nfc_init (&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices (context, devices, 8);
    if (device_count <= 0)
	errx (EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
	device = nfc_open (context, devices[d]);
	if (!device) {
	    warnx ("nfc_open() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}

	tags = freefare_get_tags (device);
	if (!tags) {
	    nfc_close (device);
	    errx (EXIT_FAILURE, "Error listing Mifare Classic tag.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    switch (freefare_get_tag_type (tags[i])) {
	    case MIFARE_CLASSIC_1K:
	    case MIFARE_CLASSIC_4K:
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
		enum freefare_tag_type tt = freefare_get_tag_type (tags[i]);
		at_block = 0;

		if (format_options.fast) {
		    printf (START_FORMAT_N, (tt == MIFARE_CLASSIC_1K) ? 1 : 2);
		    if (!try_format_sector (tags[i], 0x00))
			break;

		    if (tt == MIFARE_CLASSIC_4K)
			if (!try_format_sector (tags[i], 0x10))
			    break;

		    printf (DONE_FORMAT);
		    continue;
		}
		switch (tt) {
		case MIFARE_CLASSIC_1K:
		    mod_block = 4;
		    if (!format_mifare_classic_1k (tags[i]))
			error = 1;
		    break;
		case MIFARE_CLASSIC_4K:
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
	nfc_close (device);
    }

    nfc_exit (context);
    exit (error);
}
