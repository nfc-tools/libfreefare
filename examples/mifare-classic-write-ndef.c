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
#include <strings.h>

#include <nfc/nfc.h>

#include <freefare.h>

#define MIN(a,b) ((a < b) ? a: b)

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

struct mifare_classic_key_and_type {
    MifareClassicKey key;
    MifareClassicKeyType type;
};

const MifareClassicKey mad_key_a = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
};
const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

const uint8_t ndef_msg[33] = {
    0xd1, 0x02, 0x1c, 0x53, 0x70, 0x91, 0x01, 0x09,
    0x54, 0x02, 0x65, 0x6e, 0x4c, 0x69, 0x62, 0x6e,
    0x66, 0x63, 0x51, 0x01, 0x0b, 0x55, 0x03, 0x6c,
    0x69, 0x62, 0x6e, 0x66, 0x63, 0x2e, 0x6f, 0x72,
    0x67
};

int
search_sector_key (MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey *key, MifareClassicKeyType *key_type)
{
    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sector);

    /*
     * FIXME: We should not assume that if we have full access to trailer block
     *        we also have a full access to data blocks.
     */
    mifare_classic_disconnect (tag);
    for (size_t i = 0; i < (sizeof (default_keys) / sizeof (MifareClassicKey)); i++) {
	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_A))) {
	    if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_A))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_A;
		return 1;
	    }
	}
	mifare_classic_disconnect (tag);

	if ((0 == mifare_classic_connect (tag)) && (0 == mifare_classic_authenticate (tag, block, default_keys[i], MFC_KEY_B))) {
	    if ((1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYA, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B)) &&
		(1 == mifare_classic_get_trailer_block_permission (tag, block, MCAB_WRITE_KEYB, MFC_KEY_B))) {
		memcpy (key, &default_keys[i], sizeof (MifareClassicKey));
		*key_type = MFC_KEY_B;
		return 1;
	    }
	}
	mifare_classic_disconnect (tag);
    }

    warnx ("No known authentication key for sector 0x%02x\n", sector);
    return 0;
}

int
fix_mad_trailer_block (MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey key, MifareClassicKeyType key_type)
{
    MifareClassicBlock block;
    mifare_classic_trailer_block (&block, mad_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
    if (mifare_classic_authenticate (tag, mifare_classic_sector_last_block (sector), key, key_type) < 0) {
	perror ("fix_mad_trailer_block mifare_classic_authenticate");
	return -1;
    }
    if (mifare_classic_write (tag, mifare_classic_sector_last_block (sector), block) < 0) {
	perror ("mifare_classic_write");
	return -1;
    }
    return 0;
}

int
main(int argc, char *argv[])
{
    int error = 0;
    nfc_device_t *device = NULL;
    MifareTag *tags = NULL;
    Mad mad;

    (void)argc;
    (void)argv;

    struct mifare_classic_key_and_type *card_write_keys;
    if (!(card_write_keys = malloc (40 * sizeof (*card_write_keys)))) {
	err (EXIT_FAILURE, "malloc");
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

	printf ("Found %s with UID %s.  Write NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	fgets (buffer, BUFSIZ, stdin);
	bool write_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	if (write_ndef) {
	    switch (freefare_get_tag_type (tags[i])) {
		case CLASSIC_4K:
		    if (!search_sector_key (tags[i], 0x10, &(card_write_keys[0x10].key), &(card_write_keys[0x10].type))) {
			error = 1;
			goto error;
		    }
		    /* fallthrough */
		case CLASSIC_1K:
		    if (!search_sector_key (tags[i], 0x00, &(card_write_keys[0x00].key), &(card_write_keys[0x00].type))) {
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
			if (card_write_keys[0x10].type != MFC_KEY_B) {
			    if( 0 != fix_mad_trailer_block( tags[i], 0x10, card_write_keys[0x10].key, card_write_keys[0x10].type)) {
				error = 1;
				goto error;
			    }
			    memcpy (&(card_write_keys[0x10].key), &default_keyb, sizeof (MifareClassicKey));
			    card_write_keys[0x10].type = MFC_KEY_B;
			}
			/* fallthrough */
		    case CLASSIC_1K:
			if (card_write_keys[0x00].type != MFC_KEY_B) {
			    if( 0 != fix_mad_trailer_block( tags[i], 0x00, card_write_keys[0x00].key, card_write_keys[0x00].type)) {
				error = 1;
				goto error;
			    }
			    memcpy (&(card_write_keys[0x00].key), &default_keyb, sizeof (MifareClassicKey));
			    card_write_keys[0x00].type = MFC_KEY_B;
			}
			break;
		    default:
			/* Keep compiler quiet */
			break;
		}
	    }

	    size_t encoded_size;
	    uint8_t *tlv_data = tlv_encode (3, ndef_msg, sizeof (ndef_msg), &encoded_size);

	    /*
	     * At his point, we should have collected all information needed to
	     * succeed.  However, some sectors may be unaccessible if the card
	     * is not blank, so mark them as used in the MAD.
	     */

	    /*
	     * TODO Load and keep any existing MAD on the target.  In this
	     *      case, only can free sectors for keys.
	     */

	    if (!(mad = mad_new ((freefare_get_tag_type (tags[i]) == CLASSIC_4K) ? 2 : 1))) {
		perror ("mad_new");
		error = 1;
		goto error;
	    }

	    MadAid reserved = {
		.application_code = 0xff,
		.function_cluster_code = 0xff
	    };
	    for (size_t s = 40; s; s--) {
		if (s == 0x10) continue;
		if (!search_sector_key (tags[i], s, &(card_write_keys[s].key), &(card_write_keys[s].type))) {
		    mad_set_aid (mad, s, reserved);
		}
	    }

	    MadAid aid = {
		.function_cluster_code = 0xe1,
		.application_code = 0x03
	    };

	    MifareClassicSectorNumber *sectors = mifare_application_alloc (mad, aid, encoded_size);
	    if (!sectors) {
		perror ("mifare_application_alloc");
		error = EXIT_FAILURE;
		goto error;
	    }

	    if (mad_write (tags[i], mad, card_write_keys[0x00].key, card_write_keys[0x10].key) < 0) {
		perror ("mad_write");
		error = EXIT_FAILURE;
		goto error;
	    }

	    if ((ssize_t) encoded_size != mad_application_write (tags[i], mad, aid, tlv_data, encoded_size, card_write_keys[sectors[0]].key, card_write_keys[sectors[0]].type)) {
		perror ("mad_application_write");
		error = EXIT_FAILURE;
		goto error;
	    }

	    int s = 0;

	    while (sectors[s]) {
		MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
		MifareClassicBlock block_data;
		mifare_classic_trailer_block (&block_data, default_keyb, 0x0, 0x0, 0x0, 0x6, 0x40, default_keyb);
		if (mifare_classic_authenticate (tags[i], block, card_write_keys[sectors[s]].key, card_write_keys[sectors[s]].type) < 0) {
		    perror ("mifare_classic_authenticate");
		    error = EXIT_FAILURE;
		    goto error;
		}
		if (mifare_classic_write (tags[i], block, block_data) < 0) {
		    perror ("mifare_classic_write");
		    error = EXIT_FAILURE;
		    goto error;
		}
		s++;
	    }

	    free (sectors);

	    free (tlv_data);

	    free (mad);
	}

error:
	free (tag_uid);
    }

    freefare_free_tags (tags);
    nfc_disconnect (device);
    }

    free (card_write_keys);

    exit (error);
}
