/*
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

#ifndef __FREEFARE_INTERNAL_H__
#define __FREEFARE_INTERNAL_H__

struct mad_sector_0x00;
struct mad_sector_0x10;

void		 crc8 (uint8_t *crc, const uint8_t value);
MifareTag	 mifare_classic_tag_new (void);
void		 mifare_classic_tag_free (MifareTag tag);
MifareTag	 mifare_ultralight_tag_new (void);
void		 mifare_ultralight_tag_free (MifareTag tag);
uint8_t		 sector_0x00_crc8 (Mad mad);
uint8_t		 sector_0x10_crc8 (Mad mad);

#define MIFARE_ULTRALIGHT_PAGE_COUNT 16

/*
 * This structure is common to all supported MIFARE targets but shall not be
 * used directly (it's some kind of abstract class).  All members in this
 * structure are initialized by freefare_get_tags().
 *
 * Extra members in derived classes are initialized in the correpsonding
 * mifare_*_connect() function.
 */
struct mifare_tag {
    nfc_device_t *device;
    nfc_iso14443a_info_t info;
    enum mifare_tag_type type;
    int active;
};

struct mifare_classic_tag {
    struct mifare_tag __tag;

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

struct mifare_ultralight_tag {
    struct mifare_tag __tag;

    /* mifare_ultralight_read() reads 4 pages at a time (wrapping) */
    MifareUltralightPage cache[MIFARE_ULTRALIGHT_PAGE_COUNT + 3];
    uint8_t cached_pages[MIFARE_ULTRALIGHT_PAGE_COUNT];
};

/*
 * MifareTag assertion macros
 *
 * This macros provide a simple and unified way to perform various tests at the
 * beginning of the different targets functions.
 */
#define ASSERT_ACTIVE(tag) do { if (!tag->active) return errno = ENXIO, -1; } while (0)
#define ASSERT_INACTIVE(tag) do { if (tag->active) return errno = ENXIO, -1; } while (0)

#define ASSERT_MIFARE_ULTRALIGHT(tag) do { if (tag->type != ULTRALIGHT) return errno = ENODEV, -1; } while (0)
#define ASSERT_MIFARE_CLASSIC(tag) do { if (tag->type != CLASSIC_1K) return errno = ENODEV, -1; } while (0)

/* 
 * MifareTag cast macros 
 *
 * This macros are intended to provide a convenient way to cast abstract
 * MifareTag structures to concrete Tags (e.g. MIFARE Classic tag).
 */
#define MIFARE_CLASSIC(tag) ((struct mifare_classic_tag *) tag)
#define MIFARE_ULTRALIGHT(tag) ((struct mifare_ultralight_tag *) tag)

#endif /* !__FREEFARE_INTERNAL_H__ */
