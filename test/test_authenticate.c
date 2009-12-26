#include "test.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nfc/nfc.h>

DEFINE_TEST(test_authenticate)
{
    int res;
    MifareClassicTag tag;

    do {
	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);

	MifareClassicKey k = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
	res = mifare_classic_authenticate (tag, 0x00, k, MFC_KEY_A);
	assertEqualInt (res, 0);

    } while (0);

    mifare_classic_test_teardown (tag);
}

