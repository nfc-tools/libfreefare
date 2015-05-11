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
 * following documents:
 *
 * MIFARE Standard Card IC
 * MF1ICS50 Functional specification
 * Rev. 5.3 - 29 January 2008
 *
 * MIFARE Standard 4kByte Card IC
 * MF1ICS70 Functional specification
 * Rev. 4.1 - 29 January 2008
 *
 * Making the Best of Mifare Classic
 * Wouter Teepe (Radboud University Nijmegen)
 * October 6, 2008
 *
 * Mifare Std as NFC Forum Enabled Tag
 * Extensions for Mifare standard 1k/4k as NFC Forum Enable Tag
 * Rev. 1.1 — 21 August 2007
 */

#include "config.h"

#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif

#if defined(HAVE_SYS_ENDIAN_H)
#  include <sys/endian.h>
#endif

#if defined(HAVE_ENDIAN_H)
#  include <endian.h>
#endif

#if defined(HAVE_COREFOUNDATION_COREFOUNDATION_H)
#  include <CoreFoundation/CoreFoundation.h>
#endif

#if defined(HAVE_BYTESWAP_H)
#  include <byteswap.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef WITH_DEBUG
#  include <libutil.h>
#endif

#include <freefare.h>
#include "freefare_internal.h"

#define MC_OK             0x0A

#define MC_AUTH_A         0x60
#define MC_AUTH_B         0x61
#define MC_READ           0x30
#define MC_WRITE          0xA0
#define MC_TRANSFER       0xB0
#define MC_DECREMENT      0xC0
#define MC_INCREMENT      0xC1
#define MC_RESTORE        0xC2

#define CLASSIC_TRANSCEIVE(tag, msg, res) CLASSIC_TRANSCEIVE_EX(tag, msg, res, 0)

#define CLASSIC_TRANSCEIVE_EX(tag, msg, res, disconnect) \
    do { \
	errno = 0; \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	int _res; \
	if ((_res = nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, __##res##_size, 0)) < 0) { \
	    if (disconnect) { \
		tag->active = false; \
	    } \
	    if (_res == NFC_EMFCAUTHFAIL) \
		return errno = EACCES, -1; \
	    return errno = EIO, -1; \
	} \
	__##res##_n = _res; \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
    } while (0)


/* Public Key A value of NFC Forum sectors */
const MifareClassicKey mifare_classic_nfcforum_public_key_a = {
    0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7
};

union mifare_classic_block {
    unsigned char data[16];
    struct {
	uint32_t value;
	uint32_t value_;
	uint32_t value__;
	MifareClassicBlockNumber address;
	MifareClassicBlockNumber address_;
	MifareClassicBlockNumber address__;
	MifareClassicBlockNumber address___;
    } value;
    struct {
	MifareClassicKey key_a;
	uint8_t access_bits[3];
	uint8_t gpb;
	MifareClassicKey key_b;
    } trailer;
};

typedef unsigned char MifareClassicAccessBits;

unsigned char mifare_data_access_permissions[] = {
    /*
     *                          [ Key A ]         [ Key B ]
     *                              |                 |
     *                 ,----------- r(ead)            |
     *                 |,---------- w(rite)           |
     *                 ||,--------- d(ecrement)       |
     *                 |||,-------- i(ncrement)       |
     *                 ||||                           |
     *                 |||| ,------------------------ r
     *   ,----- C3     |||| |,----------------------- w
     *   |,---- C2     |||| ||,---------------------- d
     *   ||,--- C1     |||| |||,--------------------- i
     *   |||           |||| ||||
     * 0b000	0b 1111 1111 */	0xff, /* Default (blank card) */
    /* 0b001 	0b 1000 1100 */	0x8c,
    /* 0b010	0b 1000 1000 */	0x88,
    /* 0b011	0b 1010 1111 */	0xaf,
    /* 0b100	0b 1010 1010 */	0xaa,
    /* 0b101	0b 0000 1000 */	0x08,
    /* 0b110	0b 0000 1100 */	0x0c,
    /* 0b111	0b 0000 0000 */	0x00
};

uint16_t mifare_trailer_access_permissions[] = {
    /*
     *                          [ Key A ]     [ Access bits ]    [ Key B ]
     *                              |                |                |
     *                 ,----------- read A           |                |
     *                 |,---------- read B           |                |
     *                 ||,--------- write A          |                |
     *                 |||,-------- write B          |                |
     *                 ||||                          |                |
     *                 |||| ,----------------------- read A           |
     *                 |||| |,---------------------- read B           |
     *                 |||| ||,--------------------- write A          |
     *                 |||| |||,-------------------- write B          |
     *                 |||| ||||                                      |
     *                 |||| |||| ,----------------------------------- read A
     *   ,----- C3     |||| |||| |,---------------------------------- read B
     *   |,---- C2     |||| |||| ||,--------------------------------- write A
     *   ||,--- C1     |||| |||| |||,-------------------------------- write B
     *   |||           |||| |||| ||||
     * 0b000	0b 0010 1000 1010*/	0x28a,
    /* 0b001 	0b 0001 1100 0001*/	0x1c1,
    /* 0b010	0b 0000 1000 1000*/	0x088,
    /* 0b011	0b 0000 1100 0000*/	0x0c0,
    /* 0b100	0b 0010 1010 1010*/	0x2aa, /* Default (blank card) */
    /* 0b101	0b 0000 1101 0000*/	0x0d0,
    /* 0b110	0b 0001 1101 0001*/	0x1d1,
    /* 0b111	0b 0000 1100 0000*/	0x0c0
};


/*
 * Private functions
 */

int		 get_block_access_bits_shift (MifareClassicBlockNumber block, MifareClassicBlockNumber trailer);
int		 get_block_access_bits (FreefareTag tag, const MifareClassicBlockNumber block, MifareClassicAccessBits *block_access_bits);


/*
 * Memory management functions.
 */

/*
 * Allocates and initialize a MIFARE Classic tag.
 */

FreefareTag
mifare_classic_tag_new (void)
{
    return malloc (sizeof (struct mifare_classic_tag));
}

/*
 * Free the provided tag.
 */
void
mifare_classic_tag_free (FreefareTag tag)
{
    free (tag);
}


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleanups after using
 * the target.
 */

/*
 * Establish connection to the provided tag.
 */
int
mifare_classic_connect (FreefareTag tag)
{
    ASSERT_INACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    nfc_target pnti;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if (nfc_initiator_select_passive_target (tag->device, modulation, tag->info.nti.nai.abtUid, tag->info.nti.nai.szUidLen, &pnti) >= 0) {
	tag->active = 1;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}

/*
 * Terminate connection with the provided tag.
 */
int
mifare_classic_disconnect (FreefareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    if (nfc_initiator_deselect_target (tag->device) >= 0) {
	tag->active = 0;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}


/*
 * Card manipulation functions
 *
 * The following functions perform direct communication with the connected
 * MIFARE card.
 */

/*
 * Send an authentification command to the provided MIFARE target.
 */
int
mifare_classic_authenticate (FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 12);
    BUFFER_INIT (res, 1);

    if (key_type == MFC_KEY_A)
	BUFFER_APPEND (cmd, MC_AUTH_A);
    else
	BUFFER_APPEND (cmd, MC_AUTH_B);

    BUFFER_APPEND(cmd, block);
    BUFFER_APPEND_BYTES (cmd, key, 6);
    // To support both 4-byte & 7-byte UID cards:
    BUFFER_APPEND_BYTES (cmd, tag->info.nti.nai.abtUid + tag->info.nti.nai.szUidLen - 4, 4);

    CLASSIC_TRANSCEIVE_EX (tag, cmd, res, 1);

    MIFARE_CLASSIC(tag)->cached_access_bits.sector_trailer_block_number = -1;
    MIFARE_CLASSIC(tag)->cached_access_bits.sector_access_bits = 0x00;
    MIFARE_CLASSIC(tag)->last_authentication_key_type = key_type;

    return (BUFFER_SIZE (res) == 0) ? 0 : res[0];
}

/*
 * Read data from the provided MIFARE target.
 */
int
mifare_classic_read (FreefareTag tag, const MifareClassicBlockNumber block, MifareClassicBlock *data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_ALIAS (res, data, sizeof(MifareClassicBlock));

    BUFFER_APPEND (cmd, MC_READ);
    BUFFER_APPEND (cmd, block);

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_classic_init_value (FreefareTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr)
{
    union mifare_classic_block b;

    uint32_t le_value = htole32 ((uint32_t)value);

    b.value.value = le_value;
    b.value.value_ = ~le_value;
    b.value.value__ = le_value;

    b.value.address = adr;
    b.value.address_ = ~adr;
    b.value.address__ = adr;
    b.value.address___ = ~adr;

    if (mifare_classic_write (tag, block, b.data) < 0)
	return -1;

    return 0;
}

int
mifare_classic_read_value (FreefareTag tag, const MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr)
{
    union mifare_classic_block b;

    if (mifare_classic_read (tag, block, &b.data) < 0)
	return -1;

    if ((b.value.value ^ (uint32_t)~b.value.value_) || (b.value.value != b.value.value__)) {
	errno = EIO;
	return -1;
    }

    if ((b.value.address ^ (uint8_t)~b.value.address_) || (b.value.address != b.value.address__) || (b.value.address_ != b.value.address___)) {
	errno = EIO;
	return -1;
    }

    if (value)
	*value = le32toh (b.value.value);

    if (adr)
	*adr =  b.value.address;

    return 0;
}

/*
 * Write data to the provided MIFARE target.
 */
int
mifare_classic_write (FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 2 + sizeof (MifareClassicBlock));
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, MC_WRITE);
    BUFFER_APPEND (cmd, block);
    BUFFER_APPEND_BYTES (cmd, data, sizeof (MifareClassicBlock));

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    return (BUFFER_SIZE (res) == 0) ? 0 : res[0];
}

/*
 * Increment the given value block by the provided amount into the internal
 * data register.
 */
int
mifare_classic_increment (FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, MC_INCREMENT);
    BUFFER_APPEND (cmd, block);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (amount));

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    return (BUFFER_SIZE (res) == 0) ? 0 : res[0];
}

/*
 * Decrement the given value block by the provided amount into the internal
 * data register.
 */
int
mifare_classic_decrement (FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, MC_DECREMENT);
    BUFFER_APPEND (cmd, block);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (amount));

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    return (BUFFER_SIZE (res) == 0) ? 0 : res[0];
}

/*
 * Store the provided block to the internal data register.
 */
int
mifare_classic_restore (FreefareTag tag, const MifareClassicBlockNumber block)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    /*
     * Same length as the increment and decrement commands but only the first
     * two bytes are actually used.  The 4 bytes after the block number are
     * meaningless but required (NULL-filled).
     */
    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, MC_RESTORE);
    BUFFER_APPEND (cmd, block);
    BUFFER_APPEND (cmd, 0x00);
    BUFFER_APPEND (cmd, 0x00);
    BUFFER_APPEND (cmd, 0x00);
    BUFFER_APPEND (cmd, 0x00);

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    return (BUFFER_SIZE (res) == 0) ? 0 : res[0];
}

/*
 * Store the internal data register to the provided block.
 */
int
mifare_classic_transfer (FreefareTag tag, const MifareClassicBlockNumber block)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_CLASSIC (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, MC_TRANSFER);
    BUFFER_APPEND (cmd, block);

    CLASSIC_TRANSCEIVE (tag, cmd, res);

    /*
     * Depending on the device we are using, on success, the TRANSFER command
     * returns either no data (e.g. touchatag) or a 1 byte response, 0x0A,
     * meaning that the action was performed correctly (e.g. Snapper Feeder,
     * SCL 3711).
     */
    if (!BUFFER_SIZE (res) || ((BUFFER_SIZE (res) == 1) && (res[0] = MC_OK)))
	return 0;
    else
	return res[0];
}


/*
 * Access bit manipulation functions
 *
 * The following functions provide a convenient API for reading MIFARE card
 * access bits.  A cache system makes these functions query a single time the
 * MIFARE card regardless of the number of information requested between two
 * authentications (i.e. for the current sector).
 */

/*
 * Given a block, determine the rank of applicable access bits in the trailer
 * block.
 *
 * For 4 blocks sectors, each access bit applies to a single block; but for 16
 * blocks sectors (second part of MIFARE Classic 4k),  the first 3 access bits
 * apply to 5 blocks, and the last access bits apply to the trailer block:
 *
 *                               Sector | Access bits  | Shift
 * -------------------------------------+--------------+-------
 *      4, 128, 129, 130, 131, 132, 144 | ---x---x---x | 0
 *   1, 5, 133, 134, 135, 136, 137      | --x---x---x- | 1
 *   2, 6, 138, 138, 140, 141, 142      | -x---x---x-- | 2
 *   3, 7, 143                          | x---x---x--- | 3
 *
 */
int
get_block_access_bits_shift (MifareClassicBlockNumber block, MifareClassicBlockNumber trailer)
{
    if (block == trailer) {
	return 3;
    } else {
	if (block < 128)
	    return block % 4;
	else
	    return ((block - 128) % 16) / 5;
    }
}

/*
 * Fetch access bits for a given block from the block's sector's trailing
 * block.
 */
int
get_block_access_bits (FreefareTag tag, const MifareClassicBlockNumber block, MifareClassicAccessBits *block_access_bits)
{
    /*
     * The first block which holds the manufacturer block seems to have
     * inconsistent access bits.
     */
    if (block == 0) {
	errno = EINVAL;
	return -1;
    }

    uint16_t sector_access_bits, sector_access_bits_;

    MifareClassicBlockNumber trailer = mifare_classic_sector_last_block (mifare_classic_block_sector (block));

    /*
     * The trailer block contains access bits for the whole sector in a 3 bytes
     * structure that holds 2 times the permissions (once inverted, once
     * not-inverted).
     *
     * First we get these bytes, and check the inverted and non-inverted
     * permissions match.  A cache mechanism prevents many read access to the
     * NFC target if the function is called multiple times on the same block.
     */
    if (MIFARE_CLASSIC(tag)->cached_access_bits.sector_trailer_block_number == trailer) {
	/* cache hit! */
	sector_access_bits = MIFARE_CLASSIC(tag)->cached_access_bits.sector_access_bits;
    } else {

	MifareClassicBlock trailer_data;
	if (mifare_classic_read (tag, trailer, &trailer_data) < 0) {
	    return -1;
	}

	sector_access_bits_ = trailer_data[6] | ((trailer_data[7] & 0x0f) << 8) | 0xf000;
	sector_access_bits  = ((trailer_data[7] & 0xf0) >> 4) | (trailer_data[8] << 4);

	if (sector_access_bits ^ (uint16_t)~sector_access_bits_) {
	    /* Sector locked */
	    errno = EIO;
	    return -1;
	}
	MIFARE_CLASSIC(tag)->cached_access_bits.sector_trailer_block_number = trailer;
	MIFARE_CLASSIC(tag)->cached_access_bits.block_number = -1;
	MIFARE_CLASSIC(tag)->cached_access_bits.sector_access_bits = sector_access_bits;
    }

    /*
     * To ease permissions lookup, related permission bits which are not
     * contiguous are assembled in a quartet.
     */
    if (MIFARE_CLASSIC(tag)->cached_access_bits.block_number == block) {
	/* cache hit! */
	*block_access_bits = MIFARE_CLASSIC(tag)->cached_access_bits.block_access_bits;
    } else {
	*block_access_bits = 0;
	/*                                   ,-------C3
	 *                                   |,------C2
	 *                                   ||,---- C1
	 *                                   |||                     */
	uint16_t block_access_bits_mask = 0x0111 << get_block_access_bits_shift (block, trailer);
	/*                                   |||
	 *                                   ||`---------------.
	 *                                   |`---------------.|
	 *                                   `---------------.||
	 *                                                   |||     */
	if (sector_access_bits & block_access_bits_mask & 0x000f) *block_access_bits |= 0x01;  /* C1 */
	if (sector_access_bits & block_access_bits_mask & 0x00f0) *block_access_bits |= 0x02;  /* C2 */
	if (sector_access_bits & block_access_bits_mask & 0x0f00) *block_access_bits |= 0x04;  /* C3 */

	MIFARE_CLASSIC(tag)->cached_access_bits.block_number = block;
	MIFARE_CLASSIC(tag)->cached_access_bits.block_access_bits = *block_access_bits;
    }

    return 0;
}

/*
 * Get information about the trailer block.
 */
int
mifare_classic_get_trailer_block_permission (FreefareTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type)
{
    MifareClassicAccessBits access_bits;
    if (get_block_access_bits (tag, block, &access_bits) < 0) {
	return -1;
    }

    if (MIFARE_CLASSIC(tag)->cached_access_bits.sector_trailer_block_number == block) {
	return (mifare_trailer_access_permissions[access_bits] & (permission) << ((key_type == MFC_KEY_A) ? 1 : 0)) ? 1 : 0;
    } else {
	errno = EINVAL;
	return -1;
    }
}

/*
 * Get information about data blocks.
 */
int
mifare_classic_get_data_block_permission (FreefareTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type)
{
    MifareClassicAccessBits access_bits;
    if (get_block_access_bits (tag, block, &access_bits) < 0) {
	return -1;
    }

    if (MIFARE_CLASSIC(tag)->cached_access_bits.sector_trailer_block_number != block) {
	return ((mifare_data_access_permissions[access_bits] & (permission << ( (key_type == MFC_KEY_A) ? 4 : 0 ))) ? 1 : 0);
    } else {
	errno = EINVAL;
	return -1;
    }
}


/*
 * Miscellaneous functions
 */

/*
 * Reset a MIFARE target sector to factory default.
 */
int
mifare_classic_format_sector (FreefareTag tag, const MifareClassicSectorNumber sector)
{
    MifareClassicBlockNumber first_sector_block = mifare_classic_sector_first_block (sector);
    MifareClassicBlockNumber last_sector_block = mifare_classic_sector_last_block (sector);

    /* 
     * Check that the current key allow us to rewrite data and trailer blocks.
     */

    if (first_sector_block == 0) {
	/* First block is read-only */
	first_sector_block = 1;
    }

    for (int n = first_sector_block; n < last_sector_block; n++) {
	if (mifare_classic_get_data_block_permission(tag, n, MCAB_W, MIFARE_CLASSIC(tag)->last_authentication_key_type) != 1) {
	    return errno = EPERM, -1;
	}
    }
    if ((mifare_classic_get_trailer_block_permission(tag, last_sector_block, MCAB_WRITE_KEYA, MIFARE_CLASSIC(tag)->last_authentication_key_type) != 1) ||
	(mifare_classic_get_trailer_block_permission(tag, last_sector_block, MCAB_WRITE_ACCESS_BITS, MIFARE_CLASSIC(tag)->last_authentication_key_type) != 1) ||
	(mifare_classic_get_trailer_block_permission(tag, last_sector_block, MCAB_WRITE_KEYB, MIFARE_CLASSIC(tag)->last_authentication_key_type) != 1)) {
	return errno = EPERM, -1;
    }

    MifareClassicBlock empty_data_block;
    memset (empty_data_block, 0, sizeof (empty_data_block));

    MifareClassicBlock default_trailer_block = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Key A */
	0xff, 0x07, 0x80,                    /* Access bits */
	0x69,                                /* GPB */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff   /* Key B */
    };

    for (int n = first_sector_block; n < last_sector_block; n++) {
	if (mifare_classic_write (tag, n, empty_data_block) < 0) {
	    return errno = EIO,  -1;
	}
    }
    if (mifare_classic_write (tag, last_sector_block, default_trailer_block) < 0) {
	return errno = EIO,  -1;
    }

    return 0;
}

MifareClassicSectorNumber
mifare_classic_block_sector (MifareClassicBlockNumber block)
{
    MifareClassicSectorNumber res;

    if (block < 32 * 4)
	res = block / 4;
    else
	res = 32 + ( (block - (32 * 4)) / 16 );

    return res;
}

/*
 * Get the sector's first block number
 */
MifareClassicBlockNumber
mifare_classic_sector_first_block (MifareClassicSectorNumber sector)
{
    int res;
    if (sector < 32) {
	res = sector * 4;
    } else {
	res = 32 * 4 + (sector - 32) * 16;
    }

    return res;
}

size_t
mifare_classic_sector_block_count (MifareClassicSectorNumber sector)
{
    return (sector < 32) ? 4 : 16 ;
}

/*
 * Get the sector's last block number (aka trailer block)
 */
MifareClassicBlockNumber
mifare_classic_sector_last_block (MifareClassicSectorNumber sector)
{
    return mifare_classic_sector_first_block (sector) +
	mifare_classic_sector_block_count (sector) - 1;
}

/*
 * Generates a MIFARE trailer block.
 */
void
mifare_classic_trailer_block (MifareClassicBlock *block, const MifareClassicKey key_a, uint8_t ab_0, uint8_t ab_1, uint8_t ab_2, uint8_t ab_tb, const uint8_t gpb, const MifareClassicKey key_b)
{
    union mifare_classic_block *b = (union mifare_classic_block *)block; // *((union mifare_classic_block *)(&block));

    ab_0 = DB_AB(ab_0);
    ab_1 = DB_AB(ab_1);
    ab_2 = DB_AB(ab_2);
    ab_tb = TB_AB(ab_tb);

    memcpy (b->trailer.key_a, key_a, sizeof (MifareClassicKey));

    uint32_t access_bits = ((((( ab_0  & 0x4) >> 2) << 8) | (((ab_0  & 0x2) >> 1) << 4) | (ab_0  & 0x1)) |
			    (((((ab_1  & 0x4) >> 2) << 8) | (((ab_1  & 0x2) >> 1) << 4) | (ab_1  & 0x1)) << 1) |
			    (((((ab_2  & 0x4) >> 2) << 8) | (((ab_2  & 0x2) >> 1) << 4) | (ab_2  & 0x1)) << 2) |
			    (((((ab_tb & 0x4) >> 2) << 8) | (((ab_tb & 0x2) >> 1) << 4) | (ab_tb & 0x1)) << 3));

    uint32_t access_bits_ = ((~access_bits) & 0x00000fff);

    uint32_t ab = htole32(((access_bits << 12) | access_bits_));
    memcpy (&(b->trailer.access_bits), &ab, 3);
    b->trailer.gpb = gpb;

    memcpy (b->trailer.key_b, key_b, sizeof (MifareClassicKey));
}
