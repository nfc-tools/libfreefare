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

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <sys/types.h>

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include <freefare.h>

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
mad_new(uint8_t version)
{
    Mad mad = malloc(sizeof(*mad));

    if (!mad)
	return NULL;

    mad->version = version;
    memset(&(mad->sector_0x00), 0, sizeof(mad->sector_0x00));
    memset(&(mad->sector_0x10), 0, sizeof(mad->sector_0x10));

    return mad;
}

/*
 * Compute CRC.
 */
void
nxp_crc(uint8_t *crc, const uint8_t value)
{
    /* the original code, which used a bitwise method for calculating CRC, has
     * since been replaced by this lookup table. the original implementation can
     * be found in test_mad.c */
    /* x^8 + x^4 + x^3 + x^2 + 1 => 0x11d */
    static const uint8_t nxp_crc_lut[] = {
	0x00, 0x1D, 0x3A, 0x27, 0x74, 0x69, 0x4E, 0x53, 0xE8, 0xF5, 0xD2, 0xCF,
	0x9C, 0x81, 0xA6, 0xBB, 0xCD, 0xD0, 0xF7, 0xEA, 0xB9, 0xA4, 0x83, 0x9E,
	0x25, 0x38, 0x1F, 0x02, 0x51, 0x4C, 0x6B, 0x76, 0x87, 0x9A, 0xBD, 0xA0,
	0xF3, 0xEE, 0xC9, 0xD4, 0x6F, 0x72, 0x55, 0x48, 0x1B, 0x06, 0x21, 0x3C,
	0x4A, 0x57, 0x70, 0x6D, 0x3E, 0x23, 0x04, 0x19, 0xA2, 0xBF, 0x98, 0x85,
	0xD6, 0xCB, 0xEC, 0xF1, 0x13, 0x0E, 0x29, 0x34, 0x67, 0x7A, 0x5D, 0x40,
	0xFB, 0xE6, 0xC1, 0xDC, 0x8F, 0x92, 0xB5, 0xA8, 0xDE, 0xC3, 0xE4, 0xF9,
	0xAA, 0xB7, 0x90, 0x8D, 0x36, 0x2B, 0x0C, 0x11, 0x42, 0x5F, 0x78, 0x65,
	0x94, 0x89, 0xAE, 0xB3, 0xE0, 0xFD, 0xDA, 0xC7, 0x7C, 0x61, 0x46, 0x5B,
	0x08, 0x15, 0x32, 0x2F, 0x59, 0x44, 0x63, 0x7E, 0x2D, 0x30, 0x17, 0x0A,
	0xB1, 0xAC, 0x8B, 0x96, 0xC5, 0xD8, 0xFF, 0xE2, 0x26, 0x3B, 0x1C, 0x01,
	0x52, 0x4F, 0x68, 0x75, 0xCE, 0xD3, 0xF4, 0xE9, 0xBA, 0xA7, 0x80, 0x9D,
	0xEB, 0xF6, 0xD1, 0xCC, 0x9F, 0x82, 0xA5, 0xB8, 0x03, 0x1E, 0x39, 0x24,
	0x77, 0x6A, 0x4D, 0x50, 0xA1, 0xBC, 0x9B, 0x86, 0xD5, 0xC8, 0xEF, 0xF2,
	0x49, 0x54, 0x73, 0x6E, 0x3D, 0x20, 0x07, 0x1A, 0x6C, 0x71, 0x56, 0x4B,
	0x18, 0x05, 0x22, 0x3F, 0x84, 0x99, 0xBE, 0xA3, 0xF0, 0xED, 0xCA, 0xD7,
	0x35, 0x28, 0x0F, 0x12, 0x41, 0x5C, 0x7B, 0x66, 0xDD, 0xC0, 0xE7, 0xFA,
	0xA9, 0xB4, 0x93, 0x8E, 0xF8, 0xE5, 0xC2, 0xDF, 0x8C, 0x91, 0xB6, 0xAB,
	0x10, 0x0D, 0x2A, 0x37, 0x64, 0x79, 0x5E, 0x43, 0xB2, 0xAF, 0x88, 0x95,
	0xC6, 0xDB, 0xFC, 0xE1, 0x5A, 0x47, 0x60, 0x7D, 0x2E, 0x33, 0x14, 0x09,
	0x7F, 0x62, 0x45, 0x58, 0x0B, 0x16, 0x31, 0x2C, 0x97, 0x8A, 0xAD, 0xB0,
	0xE3, 0xFE, 0xD9, 0xC4
    };
    *crc = nxp_crc_lut[*crc ^ value];
}

uint8_t
sector_0x00_crc8(Mad mad)
{
    uint8_t crc = CRC_PRESET;

    nxp_crc(&crc, mad->sector_0x00.info);

    for (int n = 0; n < SECTOR_0X00_AIDS; n++) {
	nxp_crc(&crc, mad->sector_0x00.aids[n].application_code);
	nxp_crc(&crc, mad->sector_0x00.aids[n].function_cluster_code);
    }

    return crc;
}

uint8_t
sector_0x10_crc8(Mad mad)
{
    uint8_t crc = CRC_PRESET;

    nxp_crc(&crc, mad->sector_0x10.info);

    for (int n = 0; n < SECTOR_0X10_AIDS; n++) {
	nxp_crc(&crc, mad->sector_0x10.aids[n].application_code);
	nxp_crc(&crc, mad->sector_0x10.aids[n].function_cluster_code);
    }

    return crc;
}

/*
 * Read a MAD from the provided MIFARE tag.
 */
Mad
mad_read(FreefareTag tag)
{
    Mad mad = malloc(sizeof(*mad));

    if (!mad)
	goto error;

    /* Authenticate using MAD key A */
    if (mifare_classic_authenticate(tag, 0x03, mad_public_key_a, MFC_KEY_A) < 0) {
	goto error;
    }

    /* Read first sector trailer block */
    MifareClassicBlock data;
    if (mifare_classic_read(tag, 0x03, &data) < 0) {
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
    if (mifare_classic_read(tag, 0x01, &data) < 0)
	goto error;

    uint8_t *p = (uint8_t *) & (mad->sector_0x00);
    memcpy(p, data, sizeof(data));

    p += sizeof(data);

    if (mifare_classic_read(tag, 0x02, &data) < 0)
	goto error;
    memcpy(p, data, sizeof(data));

    uint8_t crc = mad->sector_0x00.crc;
    uint8_t computed_crc = sector_0x00_crc8(mad);
    if (crc != computed_crc)
	goto error;

    /* Read MAD data at 0x10 (MAD2) */
    if (mad->version == 2) {

	/* Authenticate using MAD key A */
	if (mifare_classic_authenticate(tag, 0x43, mad_public_key_a, MFC_KEY_A) < 0) {
	    goto error;
	}

	p = (uint8_t *) & (mad->sector_0x10);

	if (mifare_classic_read(tag, 0x40, &data) < 0)
	    goto error;
	memcpy(p, data, sizeof(data));

	p += sizeof(data);

	if (mifare_classic_read(tag, 0x41, &data) < 0)
	    goto error;
	memcpy(p, data, sizeof(data));

	p += sizeof(data);

	if (mifare_classic_read(tag, 0x42, &data) < 0)
	    goto error;
	memcpy(p, data, sizeof(data));

	crc = mad->sector_0x10.crc;
	computed_crc = sector_0x10_crc8(mad);
	if (crc != computed_crc)
	    goto error;
    }

    return mad;

error:
    free(mad);
    return NULL;
}

/*
 * Write the mad to the provided MIFARE tad using the provided Key-B keys.
 */
int
mad_write(FreefareTag tag, Mad mad, const MifareClassicKey key_b_sector_00, const MifareClassicKey key_b_sector_10)
{
    MifareClassicBlock data;

    if (mifare_classic_authenticate(tag, 0x00, key_b_sector_00, MFC_KEY_B) < 0)
	return -1;

    if ((1 != mifare_classic_get_data_block_permission(tag, 0x01, MCAB_W, MFC_KEY_B)) ||
	(1 != mifare_classic_get_data_block_permission(tag, 0x02, MCAB_W, MFC_KEY_B)) ||
	(1 != mifare_classic_get_trailer_block_permission(tag, 0x03, MCAB_WRITE_KEYA, MFC_KEY_B)) ||
	(1 != mifare_classic_get_trailer_block_permission(tag, 0x03, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B))) {
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
	if (mifare_classic_authenticate(tag, 0x40, key_b_sector_10, MFC_KEY_B) < 0)
	    return -1;

	if ((1 != mifare_classic_get_data_block_permission(tag, 0x40, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_data_block_permission(tag, 0x41, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_data_block_permission(tag, 0x42, MCAB_W, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_trailer_block_permission(tag, 0x43, MCAB_WRITE_KEYA, MFC_KEY_B)) ||
	    (1 != mifare_classic_get_trailer_block_permission(tag, 0x43, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B))) {
	    errno = EPERM;
	    return -1;
	}

	mad->sector_0x10.crc = sector_0x10_crc8(mad);

	memcpy(data, (uint8_t *) & (mad->sector_0x10), sizeof(data));
	if (mifare_classic_write(tag, 0x40, data) < 0) return -1;
	memcpy(data, (uint8_t *) & (mad->sector_0x10) + sizeof(data), sizeof(data));
	if (mifare_classic_write(tag, 0x41, data) < 0) return -1;
	memcpy(data, (uint8_t *) & (mad->sector_0x10) + sizeof(data) * 2, sizeof(data));
	if (mifare_classic_write(tag, 0x42, data) < 0) return -1;

	mifare_classic_trailer_block(&data, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, 0x00, key_b_sector_10);
	if (mifare_classic_write(tag, 0x43, data) < 0) return -1;

    }

    mad->sector_0x00.crc = sector_0x00_crc8(mad);

    if (mifare_classic_authenticate(tag, 0x00, key_b_sector_00, MFC_KEY_B) < 0) return -1;
    memcpy(data, (uint8_t *) & (mad->sector_0x00), sizeof(data));
    if (mifare_classic_write(tag, 0x01, data) < 0) return -1;
    memcpy(data, (uint8_t *) & (mad->sector_0x00) + sizeof(data), sizeof(data));
    if (mifare_classic_write(tag, 0x02, data) < 0) return -1;

    mifare_classic_trailer_block(&data, mad_public_key_a, 0x0, 0x1, 0x1, 0x6, gpb, key_b_sector_00);
    if (mifare_classic_write(tag, 0x03, data) < 0) return -1;

    return 0;
}

/*
 * Return a MAD version.
 */
int
mad_get_version(Mad mad)
{
    return mad->version;
}

/*
 * Set a MAD version.
 */
void
mad_set_version(Mad mad, const uint8_t version)
{
    if ((version == 2) && (mad->version == 1)) {
	/* We use a larger MAD so initialise the new blocks */
	memset(&(mad->sector_0x10), 0, sizeof(mad->sector_0x10));
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
mad_sector_reserved(const MifareClassicSectorNumber sector)
{
    return ((0x00 == sector) || (0x10 == sector));
}

/*
 * Free memory allocated by mad_new() and mad_read().
 */
void
mad_free(Mad mad)
{
    free(mad);
}
