/*-
 * Copyright (C) 2009, 2010, Romain Tartiere, Romuald Conty.
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
 *
 * NXP Type MF1K/4K Tag Operation
 * Storing NFC Forum data in Mifare Standard 1k/4k
 * Rev. 1.1 - 21 August 2007
 */
#include "config.h"

#include <sys/types.h>

#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <freefare.h>

#include "freefare_internal.h"

/*
 * The documentation says the preset is 0xE3 but the bits have to be mirrored:
 * 0xe3 = 1110 0011 <=> 1100 0111 = 0xc7
 */
#define CRC_PRESET 0xc7

#define SECTOR_0X00_AIDS 15
#define SECTOR_0X10_AIDS 23

struct mad_sector_0x00 {
    uint8_t crc;
    uint8_t info;
    MadAid aids[SECTOR_0X00_AIDS];
};

struct mad_sector_0x10 {
    uint8_t crc;
    uint8_t info;
    MadAid aids[SECTOR_0X10_AIDS];
};

struct mad {
    struct mad_sector_0x00 sector_0x00;
    struct mad_sector_0x10 sector_0x10;
    uint8_t version;
};

/* Public Key A value of MAD sector(s) */
const MifareClassicKey mad_public_key_a = {
    0xa0, 0xa1, 0xa2, 0xa3, 0xa4, 0xa5
};

/* AID - Administration codes: */
/* if sector is free */
const MadAid mad_free_aid = {
    .function_cluster_code = 0x00,
    .application_code = 0x00,
};
/* if sector is defect, e.g. access keys are destroyed or unknown */
const MadAid mad_defect_aid = {
    .function_cluster_code = 0x00,
    .application_code = 0x01,
};
/* if sector is reserved */
const MadAid mad_reserved_aid = {
    .function_cluster_code = 0x00,
    .application_code = 0x02,
};
/* if sector contains card holder information in ASCII format. */
const MadAid mad_card_holder_aid = {
    .function_cluster_code = 0x00,
    .application_code = 0x04,
};
/* if sector not applicable (above memory size) */
const MadAid mad_not_applicable_aid = {
    .function_cluster_code = 0x00,
    .application_code = 0x05,
};

/* NFC Forum AID */
const MadAid mad_nfcforum_aid = {
    .function_cluster_code = 0xe1,
    .application_code = 0x03,
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
    bzero (&(mad->sector_0x00), sizeof (mad->sector_0x00));
    bzero (&(mad->sector_0x10), sizeof (mad->sector_0x10));

    return mad;
}

/*
 * Compute CRC.
 */
void
nxp_crc (uint8_t *crc, const uint8_t value)
{
    /* x^8 + x^4 + x^3 + x^2 + 1 => 0x11d */
    const uint8_t poly = 0x1d;

    *crc ^= value;
    for (int current_bit = 7; current_bit >= 0; current_bit--) {
	int bit_out = (*crc) & 0x80;
	*crc <<= 1;
	if (bit_out)
	    *crc ^= poly;

    }
}

uint8_t
sector_0x00_crc8 (Mad mad)
{
    uint8_t crc = CRC_PRESET;

    nxp_crc (&crc, mad->sector_0x00.info);

    for (int n = 0; n < SECTOR_0X00_AIDS; n++) {
	nxp_crc (&crc, mad->sector_0x00.aids[n].application_code);
	nxp_crc (&crc, mad->sector_0x00.aids[n].function_cluster_code);
    }

    return crc;
}

uint8_t
sector_0x10_crc8 (Mad mad)
{
    uint8_t crc = CRC_PRESET;

    nxp_crc (&crc, mad->sector_0x10.info);

    for (int n = 0; n < SECTOR_0X10_AIDS; n++) {
	nxp_crc (&crc, mad->sector_0x10.aids[n].application_code);
	nxp_crc (&crc, mad->sector_0x10.aids[n].function_cluster_code);
    }

    return crc;
}

/*
 * Read a MAD from the provided MIFARE tag.
 */
Mad
mad_read (MifareTag tag)
{
    Mad mad = malloc (sizeof (*mad));

    if (!mad)
	goto error;

    /* Authenticate using MAD key A */
    if (mifare_classic_authenticate (tag, 0x03, mad_public_key_a, MFC_KEY_A) < 0) {
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

    uint8_t *p = (uint8_t *) &(mad->sector_0x00);
    memcpy (p, data, sizeof (data));

    p+= sizeof (data);

    if (mifare_classic_read (tag, 0x02, &data) < 0)
	goto error;
    memcpy (p, data, sizeof (data));

    uint8_t crc = mad->sector_0x00.crc;
    uint8_t computed_crc = sector_0x00_crc8 (mad);
    if (crc != computed_crc)
	goto error;

    /* Read MAD data at 0x10 (MAD2) */
    if (mad->version == 2) {

	/* Authenticate using MAD key A */
	if (mifare_classic_authenticate (tag, 0x43, mad_public_key_a, MFC_KEY_A) < 0) {
	    goto error;
	}

	p = (uint8_t *) &(mad->sector_0x10);

	if (mifare_classic_read (tag, 0x40, &data) < 0)
	    goto error;
	memcpy (p, data, sizeof (data));

	p += sizeof (data);

	if (mifare_classic_read (tag, 0x41, &data) < 0)
	    goto error;
	memcpy (p, data, sizeof (data));

	p += sizeof (data);

	if (mifare_classic_read (tag, 0x42, &data) < 0)
	    goto error;
	memcpy (p, data, sizeof (data));

	crc = mad->sector_0x10.crc;
	computed_crc = sector_0x10_crc8 (mad);
	if (crc != computed_crc)
	    goto error;
    }

    return mad;

error:
    free (mad);
    return NULL;
}

/*
 * Write the mad to the provided MIFARE tad using the provided Key-B keys.
 */
int
mad_write (MifareTag tag, Mad mad, const MifareClassicKey key_b_sector_00, const MifareClassicKey key_b_sector_10)
{
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

	mad->sector_0x10.crc = sector_0x10_crc8 (mad);

	memcpy (data, (uint8_t *)&(mad->sector_0x10), sizeof (data));
	if (mifare_classic_write (tag, 0x40, data) < 0) return -1;
	memcpy (data, (uint8_t *)&(mad->sector_0x10) + sizeof (data), sizeof (data));
	if (mifare_classic_write (tag, 0x41, data) < 0) return -1;
	memcpy (data, (uint8_t *)&(mad->sector_0x10) + sizeof (data) * 2, sizeof (data));
	if (mifare_classic_write (tag, 0x42, data) < 0) return -1;

	mifare_classic_trailer_block (&data, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, key_b_sector_10);
	if (mifare_classic_write (tag, 0x43, data) < 0) return -1;

    }

    mad->sector_0x00.crc = sector_0x00_crc8 (mad);

    if (mifare_classic_authenticate (tag, 0x00, key_b_sector_00, MFC_KEY_B) < 0) return -1;
    memcpy (data, (uint8_t *)&(mad->sector_0x00), sizeof (data));
    if (mifare_classic_write (tag, 0x01, data) < 0) return -1;
    memcpy (data, (uint8_t *)&(mad->sector_0x00) + sizeof (data), sizeof (data));
    if (mifare_classic_write (tag, 0x02, data) < 0) return -1;

    mifare_classic_trailer_block (&data, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, gpb, key_b_sector_00);
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
mad_set_version (Mad mad, const uint8_t version)
{
    if ((version == 2) && (mad->version == 1)) {
	/* We use a larger MAD so initialise the new blocks */
	bzero (&(mad->sector_0x10), sizeof (mad->sector_0x10));
    }
    mad->version = version;
}

/*
 * Return the MAD card publisher sector.
 */
MifareClassicSectorNumber
mad_get_card_publisher_sector(Mad mad)
{
    return (mad->sector_0x00.info & 0x3f);
}

/*
 * Set the MAD card publisher sector.
 */
int
mad_set_card_publisher_sector(Mad mad, const MifareClassicSectorNumber cps)
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
mad_get_aid(Mad mad, const MifareClassicSectorNumber sector, MadAid *aid)
{
    if ((sector < 1) || (sector == 0x10) || (sector > 0x27)) {
	errno = EINVAL;
	return -1;
    }

    if (sector > 0x0f) {
	if (mad->version != 2) {
	    errno = EINVAL;
	    return -1;
	}

	aid->function_cluster_code = mad->sector_0x10.aids[sector - 0x0f - 2].function_cluster_code;
	aid->application_code      = mad->sector_0x10.aids[sector - 0x0f - 2].application_code;
    } else {
	aid->function_cluster_code = mad->sector_0x00.aids[sector - 1].function_cluster_code;
	aid->application_code      = mad->sector_0x00.aids[sector - 1].application_code;
    }

    return 0;
}

/*
 * Set the provided sector's application identifier.
 */
int
mad_set_aid(Mad mad, const MifareClassicSectorNumber sector, MadAid aid)
{
    if ((sector < 1) || (sector == 0x10) || (sector > 0x27)) {
	errno = EINVAL;
	return -1;
    }

    if (sector > 0x0f) {
	if (mad->version != 2) {
	    errno = EINVAL;
	    return -1;
	}
	mad->sector_0x10.aids[sector - 0x0f - 2].function_cluster_code = aid.function_cluster_code;
	mad->sector_0x10.aids[sector - 0x0f - 2].application_code      = aid.application_code;
    } else {
	mad->sector_0x00.aids[sector - 1].function_cluster_code = aid.function_cluster_code;
	mad->sector_0x00.aids[sector - 1].application_code      = aid.application_code;
    }

    return 0;
}

bool
mad_sector_reserved (const MifareClassicSectorNumber sector)
{
    return ((0x00 == sector) || (0x10 == sector));
}

/*
 * Free memory allocated by mad_new() and mad_read().
 */
void
mad_free (Mad mad)
{
    free (mad);
}

ssize_t
mad_application_read (MifareTag tag, Mad mad, const MadAid aid, void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    ssize_t res = 0;

    MifareClassicSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareClassicSectorNumber *s = sectors;

    if (!sectors)
	return errno = EBADF, -1;

    while (*s && nbytes && (res >= 0)) {
	MifareClassicBlockNumber first_block = mifare_classic_sector_first_block (*s);
	MifareClassicBlockNumber last_block  = mifare_classic_sector_last_block (*s);

	MifareClassicBlockNumber b = first_block;
	MifareClassicBlock block;

	if (mifare_classic_authenticate (tag, first_block, key, key_type) < 0) {
	    res = -1;
	    break;
	}

	while ((b < last_block) && nbytes) {
	    size_t n = MIN (nbytes, 16);

	    if (mifare_classic_read (tag, b, &block) < 0) {
		res = -1;
		break;
	    }
	    memcpy ((uint8_t *)buf + res, &block, n);

	    nbytes -= n;
	    res += n;

	    b++;
	}

	s++;
    }

    free (sectors);
    return res;
}

ssize_t
mad_application_write (MifareTag tag, Mad mad, const MadAid aid, const void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    ssize_t res = 0;

    MifareClassicSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareClassicSectorNumber *s = sectors;

    if (!sectors)
	return errno = EBADF, -1;

    while (*s && nbytes && (res >= 0)) {
	MifareClassicBlockNumber first_block = mifare_classic_sector_first_block (*s);
	MifareClassicBlockNumber last_block  = mifare_classic_sector_last_block (*s);

	MifareClassicBlockNumber b = first_block;
	MifareClassicBlock block;

	if (mifare_classic_authenticate (tag, first_block, key, key_type) < 0) {
	    res = -1;
	    break;
	}

	while ((b < last_block) && nbytes) {
	    size_t n = MIN (nbytes, 16);
	    // Avoid overwriting existing data with uninitialized memory.
	    if (n < 16) {
		if (mifare_classic_read (tag, b, &block) < 0) {
		    res = -1;
		    break;
		}
	    }

	    memcpy (&block, (uint8_t *)buf + res, n);
	    if (mifare_classic_write (tag, b, block) < 0) {
		res = -1;
		break;
	    }

	    nbytes -= n;
	    res += n;

	    b++;
	}

	s++;
    }

    free (sectors);
    return res;

}
