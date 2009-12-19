#include "test.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nfc/nfc.h>

#include "mifare_classic.h"

DEFINE_TEST(read_sector_0)
{
    MifareClassicTag tag;
    int res ;

    do {

	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);


	MifareClassicKey k = { 0xA0, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5 };
	res = mifare_classic_authenticate (tag, 0x00, k, MFC_KEY_A);
	assertEqualInt (res, 0);


	MifareClassicBlock r;
	res = mifare_classic_read (tag, 0x00, &r);
	assertEqualInt (res, 0);

	extract_reference_file ("test_read_sector_0");

	FILE *f = fopen("test_read_sector_0", "r");
	char buffer[17];
	fgets (buffer, 17, f);

	assertEqualMem (r, buffer, 16);

	fclose (f);

    } while (0);

    mifare_classic_test_teardown (tag);
}

