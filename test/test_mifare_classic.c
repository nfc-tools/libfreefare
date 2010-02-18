#include <cutter.h>
#include <string.h>

#include <freefare.h>

#include "mifare_classic_fixture.h"

void
test_mifare_classic_authenticate (void)
{
    int res;
    MifareClassicKey k = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    res = mifare_classic_authenticate (tag, 0x00, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
}

void
test_mifare_classic_read_sector_0 (void)
{
    int res;

    cut_omit ("Requires a particular NFC tag");

    MifareClassicKey k = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
    res = mifare_classic_authenticate (tag, 0x00, k, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));


    MifareClassicBlock r;
    res = mifare_classic_read (tag, 0x00, &r);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_read() failed"));

    MifareClassicBlock e = { 0xba, 0xc7, 0x7a, 0xfc, 0xfb, 0x88, 0x04, 0x00 , 0x46, 0x5d, 0x55, 0x96, 0x41, 0x10, 0x19, 0x08 };

    cut_assert_equal_memory (e, sizeof (e), r, sizeof (r), cut_message ("Unexpected sector 0 value"));
}

void
test_mifare_classic_get_data_block_permission (void)
{
    int res;

    MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
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

    MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
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
test_mifare_classic_read_mad (void)
{
    cut_pend ("A blank MIFARE Classic does not have a MAD.  This test has to be moved in an appropriate test case.");
    Mad mad = mad_read (tag);
    cut_assert_not_null (mad, cut_message ("mad_read() failed"));
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
    memset (empty, '\x00', sizeof (empty));

    res = mifare_classic_write (tag, 0x3c, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));
    res = mifare_classic_write (tag, 0x3d, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));
    res = mifare_classic_write (tag, 0x3e, data);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    res = mifare_classic_format_sector (tag, 0x0f);
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
    MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
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
    MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
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
    MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
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
