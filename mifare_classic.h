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

#ifndef __MIFARE_CLASSIC_H__
#define __MIFARE_CLASSIC_H__

struct mifare_classic_tag;
typedef struct mifare_classic_tag *MifareClassicTag;

// struct mifare_block;
// typedef struct mifare_block *MifareClassicBlock;
typedef unsigned char MifareClassicBlock[16];

typedef unsigned char MifareClassicBlockNumber;

typedef enum { MFC_KEY_A, MFC_KEY_B } MifareClassicKeyType;
typedef unsigned char MifareClassicKey[6];

MifareClassicTag *mifare_classic_get_tags (nfc_device_t *device);
void	 mifare_classic_free_tags (MifareClassicTag *tags);

int	 mifare_classic_connect (MifareClassicTag tag);
int	 mifare_classic_disconnect (MifareClassicTag tag);

int	 mifare_classic_authenticate (MifareClassicTag tag, MifareClassicBlockNumber block, MifareClassicKey key, MifareClassicKeyType key_type);

int	 mifare_classic_read (MifareClassicTag tag, MifareClassicBlockNumber block, MifareClassicBlock *data);
int	 mifare_classic_init_value (MifareClassicTag tag, MifareClassicBlockNumber block, int32_t value, MifareClassicBlockNumber adr);
int	 mifare_classic_read_value (MifareClassicTag tag, MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr);
int	 mifare_classic_write (MifareClassicTag tag, MifareClassicBlockNumber block, MifareClassicBlock data);


int 	 mifare_classic_get_trailer_block_permission (MifareClassicTag tag, MifareClassicBlockNumber block, uint16_t permission, MifareClassicKeyType key_type);
int	 mifare_classic_get_data_block_permission (MifareClassicTag tag, MifareClassicBlockNumber block, unsigned char permission, MifareClassicKeyType key_type);
int	 mifare_classic_increment (MifareClassicTag tag, MifareClassicBlockNumber block, uint32_t amount);
int	 mifare_classic_decrement (MifareClassicTag tag, MifareClassicBlockNumber block, uint32_t amount);
int	 mifare_classic_restore (MifareClassicTag tag, MifareClassicBlockNumber block);
int	 mifare_classic_transfer (MifareClassicTag tag, MifareClassicBlockNumber block);

int	 mifare_classic_format_sector (MifareClassicTag tag, MifareClassicBlockNumber block);

/* MIFARE Classic Access Bits */
#define MCAB_R 0x8
#define MCAB_W 0x4
#define MCAB_D 0x2
#define MCAB_I 0x1

#define MCAB_READ_KEYA         0x400
#define MCAB_WRITE_KEYA        0x100
#define MCAB_READ_ACCESS_BITS  0x040
#define MCAB_WRITE_ACCESS_BITS 0x010
#define MCAB_READ_KEYB         0x004
#define MCAB_WRITE_KEYB        0x001

#endif /* !__MIFARE_CLASSIC_H__ */
