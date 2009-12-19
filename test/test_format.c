#include "test.h"

#include <err.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <nfc/nfc.h>

#include "mifare_classic.h"

DEFINE_TEST(format)
{
    int res;
    MifareClassicTag tag;

    do {
	res = mifare_classic_test_setup (&tag);
	assertEqualInt (res, 0);

	MifareClassicKey k = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	res = mifare_classic_authenticate (tag, 0x3c, k, MFC_KEY_A);
	assertEqualInt (res, 0);

	MifareClassicBlock data = {
	    0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
	    0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
	};

	MifareClassicBlock empty;
	memset (empty, '\x00', sizeof (empty));

	res = mifare_classic_write (tag, 0x3c, data);
	assertEqualInt (res, 0);
	res = mifare_classic_write (tag, 0x3d, data);
	assertEqualInt (res, 0);
	res = mifare_classic_write (tag, 0x3e, data);
	assertEqualInt (res, 0);

	res = mifare_classic_format_sector (tag, 0x03c);
	assertEqualInt (res, 0);

	res = mifare_classic_read (tag, 0x3c, &data);
	assertEqualInt (res, 0);
	assertEqualMem (data, empty, sizeof (data));

	res = mifare_classic_read (tag, 0x3d, &data);
	assertEqualInt (res, 0);
	assertEqualMem (data, empty, sizeof (data));

	res = mifare_classic_read (tag, 0x3e, &data);
	assertEqualInt (res, 0);
	assertEqualMem (data, empty, sizeof (data));

	res = mifare_classic_read (tag, 0x3f, &data);
	assertEqualInt (res, 0);
	assertEqualMem (data, "\x00\x00\x00\x00\x00\x00\xff\x07\x80\x69\xff\xff\xff\xff\xff\xff", sizeof (data));

    } while (0);

    mifare_classic_test_teardown (tag);
}

