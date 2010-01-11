#include <cutter.h>

#include <freefare.h>

void
test_mifare_classic_create_trailer_block (void)
{
    MifareClassicBlock data;

    MifareClassicKey key_a = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    MifareClassicKey key_b = { 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff };

    mifare_classic_trailer_block (&data, key_a, 0, 0, 0, 4, 0x42, key_b);

    cut_assert_equal_memory (data, sizeof (data), "\xff\xff\xff\xff\xff\xff\xff\x07\x80\x42\xde\xad\xbe\xef\xff\xff", sizeof (data));
}

