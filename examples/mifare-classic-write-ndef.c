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

const MifareClassicKey mad_key_a = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
};
const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

int
search_sector_key (MifareTag tag, MifareClassicBlockNumber block, MifareClassicKey *key, MifareClassicKeyType *key_type)
{
    for (int i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if ((1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_KEYA, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_KEYB, MFC_KEY_A))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_A;
		return 1;
	    }
	}

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if (((block == 0) || (1 == mifare_classic_get_data_block_permission (tag, block + 0, MCAB_W, MFC_KEY_B))) &&
		(1 == mifare_classic_get_data_block_permission (tag, block + 1, MCAB_W, MFC_KEY_B)) &&
		(1 == mifare_classic_get_data_block_permission (tag, block + 2, MCAB_W, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_KEYA, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block + 3, MCAB_WRITE_KEYB, MFC_KEY_B))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_B;
		return 1;
	    }
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
    MifareClassicKey key_00, key_10;
    MifareClassicKeyType key_00_type, key_10_type;
    MifareClassicBlock block;
    Mad mad;

    (void)argc;
    (void)argv;

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

	printf ("Found %s with UID %s.  Write NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	fgets (buffer, BUFSIZ, stdin);
	bool write_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	if (write_ndef) {
	    switch (freefare_get_tag_type (tags[i])) {
		case CLASSIC_4K:
		    if (!search_sector_key (tags[i], 0x40, &key_10, &key_10_type)) {
			error = 1;
			goto error;
		    }
		case CLASSIC_1K:
		    if (!search_sector_key (tags[i], 0x00, &key_00, &key_00_type)) {
			error = 1;
			goto error;
		    }
		    break;
		default:
		    /* Keep compiler quiet */
		    break;
	    }

	    if (!error) {
		/* Ensure the auth key is always a B one. If not, change it! */
		switch (freefare_get_tag_type (tags[i])) {
		    case CLASSIC_4K:
			if (key_10_type != MFC_KEY_B) {
			    mifare_classic_trailer_block (&block, mad_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
			    if (mifare_classic_authenticate (tags[i], 0x10, key_10, key_10_type) < 0) {
				perror ("mifare_classic_authenticate");
				error = 1;
				goto error;
			    }
			    if (mifare_classic_write (tags[i], 0x43, block) < 0) {
				perror ("mifare_classic_write");
				error = 1;
				goto error;
			    }
			    memcpy (&key_10, &default_keyb, sizeof (MifareClassicKey));
			    key_10_type = MFC_KEY_B;
			}
		    case CLASSIC_1K:
			if (key_00_type != MFC_KEY_B) {
			    mifare_classic_trailer_block (&block, mad_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
			    if (mifare_classic_authenticate (tags[i], 0x00, key_00, key_00_type) < 0) {
				perror ("mifare_classic_authenticate");
				error = 1;
				goto error;
			    }
			    if (mifare_classic_write (tags[i], 0x03, block) < 0) {
				perror ("mifare_classic_write");
				error = 1;
				goto error;
			    }
			    memcpy (&key_00, &default_keyb, sizeof (MifareClassicKey));
			    key_00_type = MFC_KEY_B;
			}
			break;
		    default:
			/* Keep compiler quiet */
			break;
		}
	    }

	    if (!(mad = mad_new ((freefare_get_tag_type (tags[i]) == CLASSIC_4K) ? 2 : 1))) {
		perror ("mad_new");
		error = 1;
		goto error;
	    }

	    if (mad_write (tags[i], mad, key_00, key_10) < 0) {
		perror ("mad_write");
		error = 1;
	    }

	    free (mad);
	}

error:
	free (tag_uid);
    }

    freefare_free_tags (tags);
    nfc_disconnect (device);

    exit (error);
}
