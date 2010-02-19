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

#define block_address(sector, block) ((sector * 4) + block)

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

int
try_format_sector (MifareClassicTag tag, MifareSectorNumber sector)
{
    for (int i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	printf (" s=%d i=%d \n", sector, i);
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block_address (sector, 0), default_keys[i], MFC_KEY_A))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 0;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block_address (sector, 0), default_keys[i], MFC_KEY_B))) {
	    if (0 == mifare_classic_format_sector (tag, sector)) {
		mifare_classic_disconnect (tag);
		return 0;
	    } else if (EIO == errno) {
		err (EXIT_FAILURE, "sector %d", sector);
	    }
	    mifare_classic_disconnect (tag);
	}
    }

    return -1;
}

int
main(int argc, char *argv[])
{
    int error = 0;
    nfc_device_t *device = NULL;
    MifareClassicTag *tags = NULL;
    MifareClassicTag *tag = NULL;

    device = nfc_connect (NULL);
    if (!device)
	errx (EXIT_FAILURE, "No NFC device found.");

    tags = mifare_classic_get_tags (device);
    if (!tags) {
	nfc_disconnect (device);
	errx (EXIT_FAILURE, "Error listing MIFARE classic tag.");
    }

    if (!tags[0]) {
	mifare_classic_free_tags (tags);
	nfc_disconnect (device);
	errx (EXIT_FAILURE, "No MIFARE classic tag on NFC device.");
    }

    tag = tags;

    while (*tag) {
	char *tag_uid = mifare_classic_get_uid (*tag);

	/* FIXME get the tag size */
	size_t sector_count = 15;

	for (size_t n = 0; n < sector_count; n++) {
	    if (try_format_sector (*tag, n) < 0) {
		warnx ("%s: Can't format sector %ld (0x%02lx)", tag_uid,  n, n);
		error = 1;
	    }
	}

	free(tag_uid);
	tag++;
    }

    mifare_classic_free_tags (tags);
    nfc_disconnect (device);

    exit (error);
}
