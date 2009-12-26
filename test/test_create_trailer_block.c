#include "test.h"

DEFINE_TEST(test_create_trailer_block)
{
    do {
	MifareClassicBlock data;

	MifareClassicKey key_a = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	MifareClassicKey key_b = { 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff };

	mifare_classic_trailer_block (&data, key_a, 0, 0, 0, 4, 0x42, key_b);

	assertEqualMem (data, "\xff\xff\xff\xff\xff\xff\xff\x07\x80\x42\xde\xad\xbe\xef\xff\xff", sizeof (data));

    } while (0);
}

