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
#include <strings.h>
#include <unistd.h>

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

const MifareClassicKey default_keyb = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

const uint8_t ndef_default_msg[33] = {
    0xd1, 0x02, 0x1c, 0x53, 0x70, 0x91, 0x01, 0x09,
    0x54, 0x02, 0x65, 0x6e, 0x4c, 0x69, 0x62, 0x6e,
    0x66, 0x63, 0x51, 0x01, 0x0b, 0x55, 0x03, 0x6c,
    0x69, 0x62, 0x6e, 0x66, 0x63, 0x2e, 0x6f, 0x72,
    0x67
};
uint8_t *ndef_msg;
size_t  ndef_msg_len;

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
fix_mad_trailer_block (nfc_device *device, MifareTag tag, MifareClassicSectorNumber sector, MifareClassicKey key, MifareClassicKeyType key_type)
{
    MifareClassicBlock block;
    mifare_classic_trailer_block (&block, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, default_keyb);
    if (mifare_classic_authenticate (tag, mifare_classic_sector_last_block (sector), key, key_type) < 0) {
	nfc_perror (device, "fix_mad_trailer_block mifare_classic_authenticate");
	return -1;
    }
    if (mifare_classic_write (tag, mifare_classic_sector_last_block (sector), block) < 0) {
	nfc_perror (device, "mifare_classic_write");
	return -1;
    }
    return 0;
}

void
usage(char *progname)
{
    fprintf (stderr, "usage: %s -i FILE\n", progname);
    fprintf (stderr, "\nOptions:\n");
    fprintf (stderr, "  -i     Use FILE as NDEF message to write on card (\"-\" = stdin)\n");
}

int
main(int argc, char *argv[])
{
    int error = 0;
    nfc_device *device = NULL;
    MifareTag *tags = NULL;
    Mad mad;
    MifareClassicKey transport_key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    int ch;
    char *ndef_input = NULL;
    while ((ch = getopt (argc, argv, "hi:")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit (EXIT_SUCCESS);
	    break;
	case 'i':
	    ndef_input = optarg;
	    break;
	case '?':
	    if (optopt == 'i')
		fprintf (stderr, "Option -%c requires an argument.\n", optopt);
	default:
	    usage (argv[0]);
	    exit (EXIT_FAILURE);
	}
    }

    if (ndef_input == NULL) {
        ndef_msg = (uint8_t*)ndef_default_msg;
        ndef_msg_len = sizeof(ndef_default_msg);
    } else {
	FILE* ndef_stream = NULL;
	if ((strlen (ndef_input) == 1) && (ndef_input[0] == '-')) {
            // FIXME stdin as input have to be readed and buffered in ndef_msg
	    ndef_stream = stdin;
            fprintf (stderr, "stdin as NDEF is not implemented");
            exit (EXIT_FAILURE);
	} else {
	    ndef_stream = fopen(ndef_input, "rb");
	    if (!ndef_stream) {
		fprintf (stderr, "Could not open file %s.\n", ndef_input);
		exit (EXIT_FAILURE);
	    }
	    fseek(ndef_stream, 0L, SEEK_END);
	    ndef_msg_len = ftell(ndef_stream);
            fseek(ndef_stream, 0L, SEEK_SET);

	    if (!(ndef_msg = malloc (ndef_msg_len))) {
		err (EXIT_FAILURE, "malloc");
	    }
	    if (fread (ndef_msg, 1, ndef_msg_len, ndef_stream) != ndef_msg_len) {
		fprintf (stderr, "Could not read NDEF from file: %s\n", ndef_input);
		fclose (ndef_stream);
		exit (EXIT_FAILURE);
	    }
	    fclose (ndef_stream);
	}
    }
    printf ("NDEF file is %zu bytes long.\n", ndef_msg_len);

    struct mifare_classic_key_and_type *card_write_keys;
    if (!(card_write_keys = malloc (40 * sizeof (*card_write_keys)))) {
	err (EXIT_FAILURE, "malloc");
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

	    printf ("Found %s with UID %s. Write NDEF [yN] ", freefare_get_tag_friendly_name (tags[i]), tag_uid);
	    fgets (buffer, BUFSIZ, stdin);
	    bool write_ndef = ((buffer[0] == 'y') || (buffer[0] == 'Y'));

	    for (int n = 0; n < 40; n++) {
		memcpy(card_write_keys[n].key, transport_key, sizeof (transport_key));
		card_write_keys[n].type = MFC_KEY_A;
	    }

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
			    if( 0 != fix_mad_trailer_block (device, tags[i], 0x10, card_write_keys[0x10].key, card_write_keys[0x10].type)) {
				error = 1;
				goto error;
			    }
			    memcpy (&(card_write_keys[0x10].key), &default_keyb, sizeof (MifareClassicKey));
			    card_write_keys[0x10].type = MFC_KEY_B;
			}
			/* fallthrough */
		    case CLASSIC_1K:
			if (card_write_keys[0x00].type != MFC_KEY_B) {
			    if( 0 != fix_mad_trailer_block (device, tags[i], 0x00, card_write_keys[0x00].key, card_write_keys[0x00].type)) {
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
		uint8_t *tlv_data = tlv_encode (3, ndef_msg, ndef_msg_len, &encoded_size);

		/*
		 * At his point, we should have collected all information needed to
		 * succeed.
		 */

		// If the card already has a MAD, load it.
		if ((mad = mad_read (tags[i]))) {
		    // If our application already exists, erase it.
		    MifareClassicSectorNumber *sectors, *p;
		    sectors = p = mifare_application_find (mad, mad_nfcforum_aid);
		    if (sectors) {
			while (*p) {
			    if (mifare_classic_authenticate (tags[i], mifare_classic_sector_last_block(*p), default_keyb, MFC_KEY_B) < 0) {
				nfc_perror (device, "mifare_classic_authenticate");
				error = 1;
				goto error;
			    }
			    if (mifare_classic_format_sector (tags[i], *p) < 0) {
				nfc_perror (device, "mifare_classic_format_sector");
				error = 1;
				goto error;
			    }
			    p++;
			}
		    }
		    free (sectors);
		    mifare_application_free (mad, mad_nfcforum_aid);
		} else {

		    // Create a MAD and mark unaccessible sectors in the card
		    if (!(mad = mad_new ((freefare_get_tag_type (tags[i]) == CLASSIC_4K) ? 2 : 1))) {
			perror ("mad_new");
			error = 1;
			goto error;
		    }

		    MifareClassicSectorNumber max_s;
		    switch (freefare_get_tag_type (tags[i])) {
		    case CLASSIC_1K:
			max_s = 15;
			break;
		    case CLASSIC_4K:
			max_s = 39;
			break;
		    default:
			/* Keep compiler quiet */
			break;
		    }

		    // Mark unusable sectors as so
		    for (size_t s = max_s; s; s--) {
			if (s == 0x10) continue;
			if (!search_sector_key (tags[i], s, &(card_write_keys[s].key), &(card_write_keys[s].type))) {
			    mad_set_aid (mad, s, mad_defect_aid);
			} else if ((memcmp (card_write_keys[s].key, transport_key, sizeof (transport_key)) != 0) &&
				   (card_write_keys[s].type != MFC_KEY_A)) {
			    // Revert to transport configuration
			    if (mifare_classic_format_sector (tags[i], s) < 0) {
				nfc_perror (device, "mifare_classic_format_sector");
				error = 1;
				goto error;
			    }
			}
		    }
		}

		MifareClassicSectorNumber *sectors = mifare_application_alloc (mad, mad_nfcforum_aid, encoded_size);
		if (!sectors) {
		    nfc_perror (device, "mifare_application_alloc");
		    error = EXIT_FAILURE;
		    goto error;
		}

		if (mad_write (tags[i], mad, card_write_keys[0x00].key, card_write_keys[0x10].key) < 0) {
		    nfc_perror (device, "mad_write");
		    error = EXIT_FAILURE;
		    goto error;
		}

		int s = 0;
		while (sectors[s]) {
		    MifareClassicBlockNumber block = mifare_classic_sector_last_block (sectors[s]);
		    MifareClassicBlock block_data;
		    mifare_classic_trailer_block (&block_data, mifare_classic_nfcforum_public_key_a, 0x0, 0x0, 0x0, 0x6, 0x40, default_keyb);
		    if (mifare_classic_authenticate (tags[i], block, card_write_keys[sectors[s]].key, card_write_keys[sectors[s]].type) < 0) {
			nfc_perror (device, "mifare_classic_authenticate");
			error = EXIT_FAILURE;
			goto error;
		    }
		    if (mifare_classic_write (tags[i], block, block_data) < 0) {
			nfc_perror (device, "mifare_classic_write");
			error = EXIT_FAILURE;
			goto error;
		    }
		    s++;
		}

		if ((ssize_t) encoded_size != mifare_application_write (tags[i], mad, mad_nfcforum_aid, tlv_data, encoded_size, default_keyb, MCAB_WRITE_KEYB)) {
		    nfc_perror (device, "mifare_application_write");
		    error = EXIT_FAILURE;
		    goto error;
		}

		free (sectors);

		free (tlv_data);

		free (mad);
	    }

error:
	    free (tag_uid);
	}

	freefare_free_tags (tags);
	nfc_close (device);
    }

    free (card_write_keys);
    nfc_exit(NULL);
    exit (error);
}
