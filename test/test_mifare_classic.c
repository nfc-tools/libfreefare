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

#include <cutter.h>
#include <string.h>
#include <strings.h>

#include <freefare.h>
#include "freefare_internal.h"

#include "mifare_classic_fixture.h"

void
test_mifare_classic_authenticate (void)
{
    int res;
    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, 0x00, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
}

void
test_mifare_classic_get_data_block_permission (void)
{
    int res;

    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, 0x04, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_R, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_R, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_W, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_W, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_D, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_D, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_I, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_I, MFC_KEY_B), cut_message ("Wrong permission"));

    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYA, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYA, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYA, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYA, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_ACCESS_BITS, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_ACCESS_BITS, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYB, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYB, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYB, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYB, MFC_KEY_B), cut_message ("Wrong permission"));
}

void
test_mifare_classic_get_trailer_permission (void)
{
    int res;

    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, 0x07, k, MFC_KEY_A);
    cut_assert_equal_int (res, 0, cut_message ("mifare_classic_authenticate() failed"));

    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_R, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_R, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_W, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_W, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_D, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_D, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_I, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_I, MFC_KEY_B), cut_message ("Wrong permission"));

    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYA, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYA, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYA, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYA, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_ACCESS_BITS, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_ACCESS_BITS, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYB, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYB, MFC_KEY_B), cut_message ("Wrong permission"));
    cut_assert_equal_int (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYB, MFC_KEY_A), cut_message ("Wrong permission"));
    cut_assert_equal_int (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYB, MFC_KEY_B), cut_message ("Wrong permission"));
}

void
test_mifare_classic_format (void)
{
    int res;

    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, 0x3c, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    MifareClassicBlock data = {
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    };

    MifareClassicBlock empty;
    memset (empty, 0, sizeof (empty));

    res = mifare_classic_write (tag, 0x3c, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));
    res = mifare_classic_write (tag, 0x3d, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));
    res = mifare_classic_write (tag, 0x3e, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    res = mifare_classic_format_sector (tag, mifare_classic_block_sector (0x3c));
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_format_sector() failed"));

    res = mifare_classic_read (tag, 0x3c, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (data, sizeof (data), empty, sizeof (data), cut_message ("Wrong data in formatted sector (block 1/3)"));

    res = mifare_classic_read (tag, 0x3d, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (data, sizeof (data), empty, sizeof (data), cut_message ("Wrong data in formatted sector (block 2/3)"));

    res = mifare_classic_read (tag, 0x3e, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (data, sizeof (data), empty, sizeof (data), cut_message ("Wrong data in formatted sector (block 3/3)"));

    res = mifare_classic_read (tag, 0x3f, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (data, sizeof (data),  "\x00\x00\x00\x00\x00\x00\xff\x07\x80\x69\xff\xff\xff\xff\xff\xff", sizeof (data), cut_message ("Wrong permissions in formatted sector"));

}

void
test_mifare_classic_value_block_increment (void)
{
    int res;

    MifareClassicBlockNumber block = 0x04;
    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    res = mifare_classic_init_value (tag, block, 1000, 0x00);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_init_value() failed"));

    /* Initialize value block */

    int32_t value;
    MifareClassicBlockNumber adr;
    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (1000, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));

    /* Increment by 1 */

    res = mifare_classic_increment (tag, block, 1);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_increment() failed"));

    res = mifare_classic_transfer (tag, block);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_transfer() failed"));

    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (1001, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));

    /* Increment by 10 */

    res = mifare_classic_increment (tag, block, 10);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_increment() failed"));

    res = mifare_classic_transfer (tag, block);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_transfer() failed"));

    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (1011, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));
}

void
test_mifare_classic_value_block_decrement (void)
{
    int res;

    MifareClassicBlockNumber block = 0x04;
    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
    res = mifare_classic_init_value (tag, block, 1000, 0x00);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_init_value() failed"));

    /* Initialize value block */

    int32_t value;
    MifareClassicBlockNumber adr;
    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (1000, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));

    /* Decrement */

    res = mifare_classic_decrement (tag, block, 1);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_decrement() failed"));

    res = mifare_classic_transfer (tag, block);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_transfer() failed"));

    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (999, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));

    res = mifare_classic_decrement (tag, block, 1000);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_decrement() failed"));

    res = mifare_classic_transfer (tag, block);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_transfer() failed"));

    res = mifare_classic_read_value (tag, block, &value, &adr);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read_value() failed"));
    cut_assert_equal_int (-1, value, cut_message ("Wrong value block value"));
    cut_assert_equal_int (0x00, adr, cut_message ("Wrong value block address"));
}

void
test_mifare_classic_value_block_restore (void)
{
    int res;

    MifareClassicBlockNumber block = 0x04;
    MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    /* Restore */

    MifareClassicBlock data;

    MifareClassicBlock sample = {
	0xe8, 0x03, 0x00, 0x00,
	0x17, 0xfc, 0xff, 0xff,
	0xe8, 0x03, 0x00, 0x00,
	0x00,
	0xff,
	0x00,
	0xff
    };

    MifareClassicBlock nul = {
	0x00, 0x00, 0x00, 0x00,
	0xff, 0xff, 0xff, 0xff,
	0x00, 0x00, 0x00, 0x00,
	0x00,
	0xff,
	0x00,
	0xff
    };

    res = mifare_classic_write (tag, block, sample);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    res = mifare_classic_read (tag, block, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (sample, sizeof (sample), data, sizeof (data), cut_message ("Wrong value block contents"));

    res = mifare_classic_write (tag, block+1, nul);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    res = mifare_classic_read (tag, block+1, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (nul, sizeof (sample), data, sizeof (data), cut_message ("Wrong value block contents"));

    res = mifare_classic_restore (tag, block);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_restore() failed"));

    res = mifare_classic_transfer (tag, block+1);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_transfer() failed"));

    res = mifare_classic_read (tag, block+1, &data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));
    cut_assert_equal_memory (sample, sizeof (sample), data, sizeof (data), cut_message ("Wrong value block contents"));
}

void
test_mifare_classic_get_uid (void)
{
    char *uid;

    uid = freefare_get_tag_uid (tag);

    cut_assert_not_null (uid, cut_message ("freefare_get_tag_uid() failed"));
    cut_assert_equal_int (8, strlen (uid), cut_message ("Wrong UID length"));

    free (uid);
}

void
test_mifare_classic_get_tag_friendly_name (void)
{
    const char *name = freefare_get_tag_friendly_name (tag);

    cut_assert_not_null (name, cut_message ("freefare_get_tag_friendly_name() failed"));
}

