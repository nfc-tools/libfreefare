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

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define START_FORMAT_N	"Formatting %d blocks"
#define DONE_FORMAT	" done.\n"

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
int		 try_format_sector (MifareTag tag, MifareClassicBlockNumber block);

int at_block = 0;

void
display_progress ()
{
    at_block++;
    if (0 == (at_block % 10)) {
	printf ("%d", at_block);
	fflush (stdout);
    } else if (0 == (at_block % 2)) {
	printf (".");
	fflush (stdout);
    }
}

int
format_mifare_classic_1k (MifareTag tag)
{
    printf (START_FORMAT_N, 16);
    for (int sector = 0; sector < 16; sector++) {
	if (!try_format_sector (tag, sector * 4))
	    return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
format_mifare_classic_4k (MifareTag tag)
{
    printf (START_FORMAT_N, 32 + 8);
    for (int sector = 0; sector < 32; sector++) {
	if (!try_format_sector (tag, sector * 4))
	    return 0;
    }
    for (int sector = 0; sector < 8; sector++) {
	if (!try_format_sector (tag, 128 + sector * 16))
	    return 0;
    }
    printf (DONE_FORMAT);
    return 1;
}

int
try_format_sector (MifareTag tag, MifareClassicBlockNumber block)
{
    display_progress ();
    for (int i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if (0 == mifare_classic_format_sector (tag, block)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "block %d", block);
	    }
	    mifare_classic_disconnect (tag);
	}

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if (0 == mifare_classic_format_sector (tag, block)) {
		mifare_classic_disconnect (tag);
		return 1;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "block %d", block);
	    }
	    mifare_classic_disconnect (tag);
	}
    }

    warnx ("No known authentication key for block %d", block);
    return 0;
}

int
main(int argc, char *argv[])
{
    int error = 0;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;

    device = nfc_connect (NULL);
    if (!device)
	errx (EXIT_FAILURE, "No NFC device found.");

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

	printf ("Found %s with UID %s.  Format [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	fgets (buffer, BUFSIZ, stdin);
	bool format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	if (format) {
	    at_block = 0;
	    switch (freefare_get_tag_type (tags[i])) {
		case CLASSIC_1K:
		    if (!format_mifare_classic_1k (tags[i]))
			error = 1;
		    break;
		case CLASSIC_4K:
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

    exit (error);
}
