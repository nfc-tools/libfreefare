/*-
 * Copyright (C) 2009, Romain Tartiere, Romuald Conty.
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

/*
 * This implementation was written based on information provided by the
 * following document:
 *
 * AN10787
 * MIFARE Application Directory (MAD)
 * Rev. 04 - 5 March 2009
 */

#include <stdlib.h>
#include <errno.h>
#include <string.h>

#include "mad.h"

struct aid {
    uint8_t function_cluster_code;
    uint8_t application_code;
};

struct mad_sector_0x00 {
    uint8_t crc;
    uint8_t info;
    struct aid aids[15];
};

struct mad_sector_0x10 {
    uint8_t crc;
    uint8_t info;
    struct aid aids[23];
};

struct mad {
    struct mad_sector_0x00 sector_0x00;
    struct mad_sector_0x10 sector_0x10;
    uint8_t version;
};

/* Read key A */
const MifareClassicKey mad_key_a = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
};

/*
 * Allocate an empty new MAD.
 */
Mad
mad_new (uint8_t version)
{
    Mad mad = malloc (sizeof (*mad));

    if (!mad)
	return NULL;

    mad->version = version;
    memset (&(mad->sector_0x00), '\0', sizeof (mad->sector_0x00));
    memset (&(mad->sector_0x10), '\0', sizeof (mad->sector_0x10));

    return mad;
}

/*
 * Read a MAD from the provided MIFARE tag.
 */
Mad
mad_read (MifareClassicTag tag)
{
    Mad mad = malloc (sizeof (*mad));

    if (!mad)
	goto error;

    /* Authenticate using MAD key A */
    if (mifare_classic_authenticate (tag, 0x03, mad_key_a, MFC_KEY_A) < 0) {
	goto error;
    }

    /* Read first sector trailer block */
    MifareClassicBlock data;
    if (mifare_classic_read (tag, 0x03, &data) < 0) {
	goto error;
    }
    uint8_t gpb = data[9];

    /* Check MAD availability (DA bit) */
    if (!(gpb & 0x80)) {
	goto error;
    }

    /* Get MAD version (ADV bits) */
    switch (gpb & 0x03) {
    case 0x01:
	mad->version = 1;
	break;
    case 0x02:
	mad->version = 2;
	break;
    default:
	/* MAD enabled but version not supported */
	errno = ENOTSUP;
	goto error;
    }

    /* Read MAD data at 0x00 (MAD1, MAD2) */
    if (mifare_classic_read (tag, 0x01, &data) < 0)
	goto error;
    memcpy (&(mad->sector_0x00), data, sizeof (data));

    if (mifare_classic_read (tag, 0x02, &data) < 0)
	goto error;
    memcpy (&(mad->sector_0x00) + sizeof (data), data, sizeof (data));

    /* Read MAD data at 0x10 (MAD2) */
    if (mad->version == 2) {

	/* Authenticate using MAD key A */
	if (mifare_classic_authenticate (tag, 0x43, mad_key_a, MFC_KEY_A) < 0) {
	    goto error;
	}

	if (mifare_classic_read (tag, 0x40, &data) < 0)
	    goto error;
	memcpy (&(mad->sector_0x10), data, sizeof (data));

	if (mifare_classic_read (tag, 0x41, &data) < 0)
	    goto error;
	memcpy (&(mad->sector_0x10) + sizeof (data), data, sizeof (data));

	if (mifare_classic_read (tag, 0x42, &data) < 0)
	    goto error;
	memcpy (&(mad->sector_0x10) + sizeof (data) * 2, data, sizeof (data));
    }

    /*
     * FIXME 3.7 CRC calculation states ``This code (CRC) should be checked
     * whenever the MAD is read in order to ensure data integrity''.
     */

    return mad;

error:
    free (mad);
    return NULL;
}

/*
 * Write the mad to the provided MIFARE tad using the provided Key-B keys.
 */
int
mad_write (MifareClassicTag tag, Mad mad, MifareClassicKey key_b_sector_00, MifareClassicKey key_b_sector_10)
{
    /*
     * FIXME Since the CRC SHOULD be checked, it SHOULD be written, right?
     */

    MifareClassicBlock data;

    if (mifare_classic_authenticate (tag, 0x00, key_b_sector_00, MFC_KEY_B) < 0)
	return -1;

    if ((1 != mifare_classic_get_data_block_permission (tag, 0x01, MCAB_W, MFC_KEY_B)) ||
	(1 != mifare_classic_get_data_block_permission (tag, 0x02, MCAB_W, MFC_KEY_B)) ||
	(1 != mifare_classic_get_trailer_block_permission (tag, 0x03, MCAB_WRITE_KEYA, MFC_KEY_B)) ||
	(1 != mifare_classic_get_trailer_block_permission (tag, 0x03, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B))) {
	errno = EPERM;
	return -1;
    }

    uint8_t gpb = 0x80;

    /*
     * FIXME Handle mono-application cards
     */
    gpb |= 0x40;

    /* Write MAD version */
    switch (mad->version) {
    case 1:
	gpb |= 0x01;
	break;
    case 2:
	gpb |= 0x02;
	break;
    }

    if (2 == mad->version) {
	if (mifare_classic_authenticate (tag, 0x40, key_b_sector_10, MFC_KEY_B) < 0)
	    return -1;

	if ((1 != mifare_classic_get_data_block_permission (tag, 0x40, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_data_block_permission (tag, 0x41, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_data_block_permission (tag, 0x42, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_trailer_block_permission (tag, 0x43, MCAB_WRITE_KEYA, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_trailer_block_permission (tag, 0x43, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B))) {
	    errno = EPERM;
	    return -1;
	}

	memcpy (data, &(mad->sector_0x10), sizeof (data));
	if (mifare_classic_write (tag, 0x40, data) < 0) return -1;
	memcpy (data, &(mad->sector_0x10) + sizeof (data), sizeof (data));
	if (mifare_classic_write (tag, 0x41, data) < 0) return -1;
	memcpy (data, &(mad->sector_0x10) + sizeof (data) * 2, sizeof (data));
	if (mifare_classic_write (tag, 0x42, data) < 0) return -1;

	mifare_classic_trailer_block (&data, mad_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, key_b_sector_10);
	if (mifare_classic_write (tag, 0x42, data) < 0) return -1;

    }

    if (mifare_classic_authenticate (tag, 0x00, key_b_sector_00, MFC_KEY_B) < 0) return -1;
    memcpy (data, &(mad->sector_0x00), sizeof (data));
    if (mifare_classic_write (tag, 0x01, data) < 0) return -1;
    memcpy (data, &(mad->sector_0x00) + sizeof (data), sizeof (data));
    if (mifare_classic_write (tag, 0x02, data) < 0) return -1;

    mifare_classic_trailer_block (&data, mad_key_a, 0x0, 0x1, 0x1, 0x6, gpb, key_b_sector_00);
    if (mifare_classic_write (tag, 0x03, data) < 0) return -1;

    return 0;
}

/*
 * Return a MAD version.
 */
int
mad_get_version (Mad mad)
{
    return mad->version;
}

/*
 * Set a MAD version.
 */
void
mad_set_version (Mad mad, uint8_t version)
{
    if ((version == 2) && (mad->version == 1)) {
	/* We use a larger MAD so initialise the new blocks */
	memset (&(mad->sector_0x10), '\0', sizeof (mad->sector_0x10));
    }
    mad->version = version;
}

/*
 * Return the MAD card publisher sector.
 */
MifareSector
mad_get_card_publisher_sector(Mad mad)
{
    return (mad->sector_0x00.info & 0x3f);
}

/*
 * Set the MAD card publisher sector.
 */
int
mad_set_card_publisher_sector(Mad mad, MifareSector cps)
{
    if (((mad->version == 2) && (cps > 0x27)) | (mad->version == 1) && (cps > 0x0f)) {
	errno = EINVAL;
	return -1;
    }

    mad->sector_0x00.info = (cps & 0x3f);
    return 0;
}

/*
 * Get the provided sector's application identifier.
 */
int
mad_get_aid(Mad mad, MifareSector sector, uint8_t *function_cluster_code, uint8_t *application_code)
{
    if (sector > 0x27) {
	errno = EINVAL;
	return -1;
    }

    if (sector > 0x0f) {
	if (mad->version != 2) {
	    errno = EINVAL;
	    return -1;
	}

	*function_cluster_code = mad->sector_0x10.aids[sector - 0x0f - 1].function_cluster_code;
	*application_code      = mad->sector_0x10.aids[sector - 0x0f - 1].application_code;
    } else {
	*function_cluster_code = mad->sector_0x00.aids[sector - 1].function_cluster_code;
	*application_code      = mad->sector_0x00.aids[sector - 1].application_code;
    }

    return 0;
}

/*
 * Set the provided sector's application identifier.
 */
int
mad_set_aid(Mad mad, MifareSector sector, uint8_t function_cluster_code, uint8_t application_code)
{
    if (sector > 0x27) {
	errno = EINVAL;
	return -1;
    }

    if (sector > 0x0f) {
	if (mad->version != 2) {
	    errno = EINVAL;
	    return -1;
	}
	mad->sector_0x00.aids[sector - 0x0f - 1].function_cluster_code = function_cluster_code;
	mad->sector_0x00.aids[sector - 0x0f - 1].application_code      = application_code;
    } else {
	mad->sector_0x00.aids[sector - 1].function_cluster_code = function_cluster_code;
	mad->sector_0x00.aids[sector - 1].application_code      = application_code;
    }

    return 0;
}

/*
 * Free memory allocated by mad_new() and mad_read().
 */
void
mad_free (Mad mad)
{
    free (mad);
}
