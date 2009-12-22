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
 * following documents:
 *
 * MF1ICS50 Functional specification
 * Rev. 5.3 — 29 January 2008
 *
 * Making the Best of Mifare Classic
 * Wouter Teepe (Radboud University Nijmegen)
 * October 6, 2008
 */

#include "config.h"

#if defined(HAVE_SYS_ENDIAN_H)
#  include <sys/endian.h>
#endif

#if defined(HAVE_ENDIAN_H)
#  define _BSD_SOURCE
#  include <endian.h>
#endif
#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <mifare_classic.h>

struct mifare_classic_tag {
    nfc_device_t *device;
    nfc_iso14443a_info_t info;
    int active;

    MifareClassicKeyType last_authentication_key_type;

    /*
     * The following block numbers are on 2 bytes in order to use invalid
     * address and avoid false cache hit with inconsistent data.
     */
    struct {
      int16_t sector_trailer_block_number;
      uint16_t sector_access_bits;
      int16_t block_number;
      uint8_t block_access_bits;
    } cached_access_bits;
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
/* 0b001 	0b 0001 1100 0000*/	0x1c0,
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

int	 get_block_access_bits (MifareClassicTag tag, const MifareClassicBlockNumber block, MifareClassicAccessBits *block_access_bits);


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the target.
 */

/*
 * Get a list of the MIFARE card near to the provided NFC initiator.
 *
 * The list can be freed using the mifare_classic_free_tags() function.
 */
MifareClassicTag *
mifare_classic_get_tags (nfc_device_t *device)
{
    MifareClassicTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_configure(device,NDO_ACTIVATE_FIELD,false);

    // Let the reader only try once to find a tag
    nfc_configure(device,NDO_INFINITE_SELECT,false);

    // Configure the CRC and Parity settings
    nfc_configure(device,NDO_HANDLE_CRC,true);
    nfc_configure(device,NDO_HANDLE_PARITY,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_configure(device,NDO_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target_info_t target_info;

    while (nfc_initiator_select_tag(device,NM_ISO14443A_106,NULL,0,&target_info)) {

	// Ensure the target is a MIFARE classic tag.
	if (!((target_info.nai.abtAtqa[0] == 0x00) &&
		    (target_info.nai.abtAtqa[1] == 0x04) &&
		    (target_info.nai.btSak == 0x08)) && /* NXP MIFARE Classic 1K */
		!((target_info.nai.abtAtqa[0] == 0x00) &&
		    (target_info.nai.abtAtqa[1] == 0x02) &&
		    (target_info.nai.btSak == 0x18)) && /* NXP MIFARE Classic 4K */
		!((target_info.nai.abtAtqa[0] == 0x00) &&
		    (target_info.nai.abtAtqa[1] == 0x02) &&
		    (target_info.nai.btSak == 0x38))) /* Nokia MIFARE Classic 4K - emulated */
	    continue;

	tag_count++;

	/* (Re)Allocate memory for the found MIFARE classic array */
	if (!tags) {
	    if (!(tags = malloc ((tag_count) * sizeof (MifareClassicTag) + sizeof (void *)))) {
	    	return NULL;
	    }
	} else {
	    MifareClassicTag *p = realloc (tags, (tag_count) * sizeof (MifareClassicTag) + sizeof (void *));
	    if (p)
		tags = p;
	    else
		return p; // FAIL! Return what has been found so far.
	}

	/* Allocate memory for the found MIFARE classic tag */
	if (!(tags[tag_count-1] = malloc (sizeof (struct mifare_classic_tag)))) {
	    return tags; // FAIL! Return what has been found before.
	}
	(tags[tag_count-1])->device = device;
	(tags[tag_count-1])->info = target_info.nai;
	(tags[tag_count-1])->active = 0;
	tags[tag_count] = NULL;

	nfc_initiator_deselect_tag (device);
    }

    return tags;
}

/*
 * Free the provided tag list.
 */
void
mifare_classic_free_tags (MifareClassicTag *tags)
{
    if (tags) {
    	for (int i=0; tags[i]; i++) {
	    free (tags[i]);
	}
	free (tags);
    }
}

/*
 * Establish connection to the provided tag.
 */
int
mifare_classic_connect (MifareClassicTag tag)
{
    if (tag->active) {
	errno = EINVAL;
	return -1;
    }

    nfc_target_info_t pnti;
    if (nfc_initiator_select_tag (tag->device, NM_ISO14443A_106, tag->info.abtUid, 4, &pnti)) {
	tag->active = 1;
    }
    return 0;
}

/*
 * Terminate connection with the provided tag.
 */
int
mifare_classic_disconnect (MifareClassicTag tag)
{
    if (!(tag->active)) {
	errno = EINVAL;
	return -1;
    }

    if (nfc_initiator_deselect_tag (tag->device)) {
	tag->active = 0;
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
mifare_classic_authenticate (MifareClassicTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[12];
    command[0] = (key_type == MFC_KEY_A) ? MC_AUTH_A : MC_AUTH_B;
    command[1] = block;
    memcpy (&(command[2]), key, 6);
    memcpy (&(command[8]), tag->info.abtUid, 4);

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    tag->cached_access_bits.sector_trailer_block_number = -1;
    tag->cached_access_bits.sector_access_bits = 0x00;
    tag->last_authentication_key_type = key_type;

    // No result.  The MIFARE tag just ACKed.
    return 0;
}

/*
 * Read data from the provided MIFARE target.
 */
int
mifare_classic_read (MifareClassicTag tag, const MifareClassicBlockNumber block, MifareClassicBlock *data)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[2];
    command[0] = MC_READ;
    command[1] = block;

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), *data, &n))) {
	errno = EIO;
	return -1;
    }

    return 0;
}

int
mifare_classic_init_value (MifareClassicTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr)
{
    union mifare_classic_block b;

    b.value.value = value;
    b.value.value_ = ~value;
    b.value.value__ = value;

    b.value.address = adr;
    b.value.address_ = ~adr;
    b.value.address__ = adr;
    b.value.address___ = ~adr;

    if (mifare_classic_write (tag, block, b.data) < 0)
	return -1;

    return 0;
}

int
mifare_classic_read_value (MifareClassicTag tag, const MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr)
{
    MifareClassicBlock data;
    if (mifare_classic_read (tag, block, &data) < 0)
	return -1;

    union mifare_classic_block b = *((union mifare_classic_block *)(&data));


    if ((b.value.value != (~b.value.value_)) || (b.value.value != b.value.value__)) {
	errno = EIO;
	return -1;
    }

    if ((b.value.address != (unsigned char)(~b.value.address_)) || (b.value.address != b.value.address__) || (b.value.address_ != b.value.address___)) {
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
mifare_classic_write (MifareClassicTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[2 + sizeof (MifareClassicBlock)];
    command[0] = MC_WRITE;
    command[1] = block;
    memcpy (&(command[2]), data, sizeof (MifareClassicBlock));

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    // No result.  The MIFARE tag just ACKed.
    return 0;
}

/*
 * Increment the given value block by the provided amount into the internal
 * data register.
 */
int
mifare_classic_increment (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint32_t amount)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[6];
    command[0] = MC_INCREMENT;
    command[1] = block;
    int32_t le_amount = htole32 (amount);
    memcpy(&(command[2]), &le_amount, sizeof (le_amount));

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    // No result.  The MIFARE tag just ACKed.
    return 0;
}

/*
 * Decrement the given value block by the provided amount into the internal
 * data register.
 */
int
mifare_classic_decrement (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint32_t amount)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[6];
    command[0] = MC_DECREMENT;
    command[1] = block;
    int32_t le_amount = htole32 (amount);
    memcpy(&(command[2]), &le_amount, sizeof (le_amount));

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    // No result.  The MIFARE tag just ACKed.
    return 0;
}

/*
 * Store the provided block to the internal data register.
 */
int
mifare_classic_restore (MifareClassicTag tag, const MifareClassicBlockNumber block)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[2];
    /* XXX Should be MC_RESTORE according to the MIFARE documentation. */
    command[0] = MC_STORE;
    command[1] = block;

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    // No result.  The MIFARE tag just ACKed.
    return 0;
}

/*
 * Store the internal data register to the provided block.
 */
int
mifare_classic_transfer (MifareClassicTag tag, const MifareClassicBlockNumber block)
{
    if (!tag->active) {
	errno = EINVAL;
	return -1;
    }

    unsigned char command[2];
    command[0] = MC_TRANSFER;
    command[1] = block;

    // Send command
    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, command, sizeof (command), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    // No result.  The MIFARE tag just ACKed.
    return 0;
}


/*
 * Access bit manipulation functions
 *
 * The following functions provide a convenient API for reading MIFARE card
 * access bits.  A cache system makes these functions query a single time the
 * MIFARE card regardless of the number of information requested between two
 * authentifications (i.e. for the current sector).
 */

/*
 * Fetch access bits for a given block from the block's sector's trailing
 * block.
 */
int
get_block_access_bits (MifareClassicTag tag, const MifareClassicBlockNumber block, MifareClassicAccessBits *block_access_bits)
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

    MifareClassicBlockNumber trailer = ((block) / 4) * 4 + 3;

    if (tag->cached_access_bits.sector_trailer_block_number == trailer) {
	/* cache hit! */
    	sector_access_bits = tag->cached_access_bits.sector_access_bits;
    } else {

	MifareClassicBlock trailer_data;
	if (mifare_classic_read (tag, trailer, &trailer_data) < 0) {
	    return -1;
	}

	sector_access_bits_ = trailer_data[6] | ((trailer_data[7] & 0x0f) << 8) | 0xf000;
	sector_access_bits  = ((trailer_data[7] & 0xf0) >> 4) | (trailer_data[8] << 4);

	if (sector_access_bits != (uint16_t) ~sector_access_bits_) {
	    /* Sector locked */
	    errno = EIO;
	    return -1;
	}
	tag->cached_access_bits.sector_trailer_block_number = trailer;
	tag->cached_access_bits.block_number = -1;
    	tag->cached_access_bits.sector_access_bits = sector_access_bits;
    }

    if (tag->cached_access_bits.block_number == block) {
	/* cache hit! */
	*block_access_bits = tag->cached_access_bits.block_access_bits;
    } else {
	*block_access_bits = 0;
	/*                                   ,-------C3
	 *                                   |,------C2
	 *                                   ||,---- C1  
	 *                                   |||                     */
	uint16_t block_access_bits_mask = 0x0111 << (block % 4);
	/*                                   |||
	 *                                   ||`---------------.
	 *                                   |`---------------.|
	 *                                   `---------------.||
	 *                                                   |||     */
	if (sector_access_bits & block_access_bits_mask & 0x000f) *block_access_bits |= 0x01;  /* C1 */
	if (sector_access_bits & block_access_bits_mask & 0x00f0) *block_access_bits |= 0x02;  /* C2 */
	if (sector_access_bits & block_access_bits_mask & 0x0f00) *block_access_bits |= 0x04;  /* C3 */

	tag->cached_access_bits.block_access_bits = *block_access_bits;
    }

    return 0;
}

/*
 * Get information about the trailer block.
 */
int
mifare_classic_get_trailer_block_permission (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type)
{
    MifareClassicAccessBits access_bits;
    if (get_block_access_bits (tag, block, &access_bits) < 0) {
	return -1;
    }

    if (tag->cached_access_bits.sector_trailer_block_number == block) {
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
mifare_classic_get_data_block_permission (MifareClassicTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type)
{
    MifareClassicAccessBits access_bits;
    if (get_block_access_bits (tag, block, &access_bits) < 0) {
	return -1;
    }

    if (tag->cached_access_bits.sector_trailer_block_number != block) {
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
mifare_classic_format_sector (MifareClassicTag tag, const MifareClassicBlockNumber block)
{
    MifareClassicBlockNumber first_sector_block = (block / 4) * 4;
    /* 
     * Check that the current key allow us to rewrite data and trailer blocks.
     */
    if ((mifare_classic_get_data_block_permission(tag, first_sector_block, MCAB_W, tag->last_authentication_key_type) != 1) ||
	(mifare_classic_get_data_block_permission(tag, first_sector_block + 1, MCAB_W, tag->last_authentication_key_type) != 1) ||
	(mifare_classic_get_data_block_permission(tag, first_sector_block + 2, MCAB_W, tag->last_authentication_key_type) != 1) ||
	(mifare_classic_get_trailer_block_permission(tag, first_sector_block + 3, MCAB_WRITE_KEYA, tag->last_authentication_key_type) != 1) ||
	(mifare_classic_get_trailer_block_permission(tag, first_sector_block + 3, MCAB_WRITE_ACCESS_BITS, tag->last_authentication_key_type) != 1) ||
	(mifare_classic_get_trailer_block_permission(tag, first_sector_block + 3, MCAB_WRITE_KEYB, tag->last_authentication_key_type) != 1)) {
	errno = EPERM;
	return -1;
    }

    MifareClassicBlock empty_data_block;
    memset (empty_data_block, '\x00', sizeof (empty_data_block));

    MifareClassicBlock default_trailer_block = {
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff,  /* Key A */
	0xff, 0x07, 0x80,                    /* Access bits */
	0x69,                                /* GPB */
	0xff, 0xff, 0xff, 0xff, 0xff, 0xff   /* Key B */
    };

    if ((mifare_classic_write (tag, first_sector_block, empty_data_block) < 0) ||
	(mifare_classic_write (tag, first_sector_block + 1, empty_data_block) < 0) ||
	(mifare_classic_write (tag, first_sector_block + 2, empty_data_block) < 0) ||
	(mifare_classic_write (tag, first_sector_block + 3, default_trailer_block) < 0)) {
	errno = EIO;
	return -1;
    }

    return 0;
}

/*
 * Generates a MIFARE trailer block.
 */
void
mifare_classic_trailer_block (MifareClassicBlock *block, const MifareClassicKey key_a, const uint8_t ab_0, const uint8_t ab_1, const uint8_t ab_2, const uint8_t ab_tb, const uint8_t gpb, const MifareClassicKey key_b)
{
    union mifare_classic_block *b = (union mifare_classic_block *)block; // *((union mifare_classic_block *)(&block));

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
