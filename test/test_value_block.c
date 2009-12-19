#include "test.h"

DEFINE_TEST(value_block_increment)
{
    int res;
    MifareClassicTag tag;

    do {
	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);

	MifareClassicBlockNumber block = 0x04;
	MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
	res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
	assertEqualInt (res, 0);

	res = mifare_classic_init_value (tag, block, 1000, 0x00);
	assertEqualInt (res, 0);

	/* Initialize value block */

	int32_t value;
	MifareClassicBlockNumber adr;
	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, 1000);
	assertEqualInt (adr, 0x00);

	/* Increment by 1 */

	res = mifare_classic_increment (tag, block, 1);
	assertEqualInt (res, 0);

	res = mifare_classic_transfer (tag, block);
	assertEqualInt (res, 0);

	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, 1001);
	assertEqualInt (adr, 0x00);

	/* Increment by 10 */

	res = mifare_classic_increment (tag, block, 10);
	assertEqualInt (res, 0);

	res = mifare_classic_transfer (tag, block);
	assertEqualInt (res, 0);

	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, 1011);
	assertEqualInt (adr, 0x00);
    } while (0);

    mifare_classic_test_teardown (tag);
}

DEFINE_TEST(value_block_decrement)
{
    int res;
    MifareClassicTag tag;

    do {
	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);

	MifareClassicBlockNumber block = 0x04;
	MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
	res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
	assertEqualInt (res, 0);

	res = mifare_classic_init_value (tag, block, 1000, 0x00);
	assertEqualInt (res, 0);

	/* Initialize value block */

	int32_t value;
	MifareClassicBlockNumber adr;
	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, 1000);
	assertEqualInt (adr, 0x00);

	/* Decrement */

	res = mifare_classic_decrement (tag, block, 1);
	assertEqualInt (res, 0);

	res = mifare_classic_transfer (tag, block);
	assertEqualInt (res, 0);

	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, 999);
	assertEqualInt (adr, 0x00);

	res = mifare_classic_decrement (tag, block, 1000);
	assertEqualInt (res, 0);

	res = mifare_classic_transfer (tag, block);
	assertEqualInt (res, 0);

	res = mifare_classic_read_value (tag, block, &value, &adr);
	assertEqualInt (res, 0);
	assertEqualInt (value, -1);
	assertEqualInt (adr, 0x00);

    } while (0);

    mifare_classic_test_teardown (tag);
}

DEFINE_TEST(value_block_restore)
{
    int res;
    MifareClassicTag tag;

    do {
	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);

	MifareClassicBlockNumber block = 0x04;
	MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
	res = mifare_classic_authenticate (tag, block, k, MFC_KEY_A);
	assertEqualInt (res, 0);

	/* Restore */

	extract_reference_file ("sample_value_block");
	extract_reference_file ("null_value_block");

	MifareClassicBlock data, sample, nul;
	read_data_block ("sample_value_block", &sample);
	read_data_block ("null_value_block", &nul);

	res = mifare_classic_write (tag, block, sample);
	assertEqualInt (res, 0);

	res = mifare_classic_read (tag, block, &data);
	assertEqualInt (res, 0);
	assertEqualMem (sample, data, sizeof (data));

	res = mifare_classic_write (tag, block+1, nul);
	assertEqualInt (res, 0);

	res = mifare_classic_read (tag, block+1, &data);
	assertEqualInt (res, 0);
	assertEqualMem (nul, data, sizeof (data));

	res = mifare_classic_restore (tag, block);
	assertEqualInt (res, 0);

	res = mifare_classic_transfer (tag, block+1);
	assertEqualInt (res, 0);

	res = mifare_classic_read (tag, block+1, &data);
	assertEqualInt (res, 0);
	assertEqualMem (sample, data, sizeof (data));
    } while (0);

    mifare_classic_test_teardown (tag);
}
