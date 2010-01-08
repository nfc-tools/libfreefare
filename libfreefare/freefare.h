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

#ifndef __FREEFARE_H__
#define __FREEFARE_H__

#include <sys/types.h>

#include <stdint.h>

#include <nfc/nfc.h>

#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus

struct mifare_classic_tag;
typedef struct mifare_classic_tag *MifareClassicTag;

typedef unsigned char MifareClassicBlock[16];

typedef uint8_t MifareSectorNumber;
typedef unsigned char MifareClassicBlockNumber;

typedef enum { MFC_KEY_A, MFC_KEY_B } MifareClassicKeyType;
typedef unsigned char MifareClassicKey[6];

MifareClassicTag *mifare_classic_get_tags (nfc_device_t *device);
void		 mifare_classic_free_tags (MifareClassicTag *tags);
int		 mifare_classic_connect (MifareClassicTag tag);
int		 mifare_classic_disconnect (MifareClassicTag tag);

int		 mifare_classic_authenticate (MifareClassicTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type);
int		 mifare_classic_read (MifareClassicTag tag, const MifareClassicBlockNumber block, MifareClassicBlock *data);
int		 mifare_classic_init_value (MifareClassicTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr);
int		 mifare_classic_read_value (MifareClassicTag tag, const MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr);
int		 mifare_classic_write (MifareClassicTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data);

int		 mifare_classic_increment (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_decrement (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_restore (MifareClassicTag tag, const MifareClassicBlockNumber block);
int		 mifare_classic_transfer (MifareClassicTag tag, const MifareClassicBlockNumber block);

int 		 mifare_classic_get_trailer_block_permission (MifareClassicTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type);
int		 mifare_classic_get_data_block_permission (MifareClassicTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type);

int		 mifare_classic_format_sector (MifareClassicTag tag, const MifareSectorNumber sector);
char*		 mifare_classic_get_uid(MifareClassicTag tag);

void		 mifare_classic_trailer_block (MifareClassicBlock *block, const MifareClassicKey key_a, const uint8_t ab_0, const uint8_t ab_1, const uint8_t ab_2, const uint8_t ab_tb, const uint8_t gpb, const MifareClassicKey key_b);

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

struct mad_aid {
    uint8_t application_code;
    uint8_t function_cluster_code;
};
typedef struct mad_aid MadAid;

struct mad;
typedef struct mad *Mad;

Mad		 mad_new (uint8_t version);
Mad		 mad_read (MifareClassicTag tag);
int		 mad_write (MifareClassicTag tag, Mad mad, MifareClassicKey key_b_sector_00, MifareClassicKey key_b_sector_10);
int		 mad_get_version (Mad mad);
void		 mad_set_version (Mad mad, uint8_t version);
MifareSectorNumber mad_get_card_publisher_sector(Mad mad);
int		 mad_set_card_publisher_sector(Mad mad, MifareSectorNumber cps);
int		 mad_get_aid(Mad mad, MifareSectorNumber sector, MadAid *aid);
int		 mad_set_aid(Mad mad, MifareSectorNumber sector, MadAid aid);
void		 mad_free (Mad mad);

MifareSectorNumber *mifare_application_alloc (Mad mad, MadAid aid, size_t size);
void		 mifare_application_free (Mad mad, MadAid aid);

MifareSectorNumber *mifare_application_find (Mad mad, MadAid aid);

#ifdef __cplusplus
    }
#endif // __cplusplus


#endif /* !__FREEFARE_H__ */
