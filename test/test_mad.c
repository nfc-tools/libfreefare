#include "test.h"

#include "../freefare_internal.h"

DEFINE_TEST(test_mad)
{
    int res;

    do {
	Mad mad = mad_new (1);
	assert (mad != NULL);

	if (mad) {
	    assertEqualInt (mad_get_version (mad), 1);
	    mad_set_version (mad, 2);
	    assertEqualInt (mad_get_version (mad), 2);

	    assertEqualInt (0, mad_get_card_publisher_sector (mad));

	    res = mad_set_card_publisher_sector (mad, 13);
	    assertEqualInt (res, 0);
	    assertEqualInt (13, mad_get_card_publisher_sector (mad));

	    res = mad_set_card_publisher_sector (mad, 0xff);
	    assertEqualInt (res, -1);
	    assertEqualInt (13, mad_get_card_publisher_sector (mad));

	    MadAid aid = {
		.function_cluster_code = 0,
		.application_code = 0
	    };

	    res = mad_get_aid (mad, 3, &aid);
	    assertEqualInt (res, 0);
	    assertEqualInt (aid.function_cluster_code, 0);
	    assertEqualInt (aid.application_code, 0);

	    aid.function_cluster_code = 0xc0;
	    aid.application_code = 0x42;
	    res = mad_set_aid (mad, 3, aid);
	    assertEqualInt (res, 0);

	    res = mad_get_aid (mad, 3, &aid);
	    assertEqualInt (res, 0);
	    assertEqualInt (aid.function_cluster_code, 0xc0);
	    assertEqualInt (aid.application_code, 0x42);

	    mad_free (mad);
	}

    } while (0);
}

#define CRC_PRESET 0x67

DEFINE_TEST(test_mad_crc8_basic)
{
    do {
	uint8_t crc;
	const uint8_t crc_value = 0x42;

	/* Insert data */
	crc = 0x00;
	crc8(&crc, crc_value);
	assertEqualInt (crc, crc_value);

	/* Insert data with leading zeros */
	crc = 0x00;
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, crc_value);
	assertEqualInt (crc, crc_value);

	/* Check integrity */
	crc = CRC_PRESET;
	crc8(&crc, crc_value);
	crc8(&crc, 0x00);
	uint8_t save = crc;

	crc = CRC_PRESET;
	crc8(&crc, crc_value);
	crc8(&crc, save);
	assertEqualInt (crc, 0x00);

    } while (0);
}

/*
 * The following MAD values where extracted from documentation.
 */
DEFINE_TEST(test_mad_crc8_doc_example)
{
    do {
	/* Preset */
	uint8_t crc = CRC_PRESET;

	/* Block 1 -- 0x01 - 0x07 */
	crc8(&crc, 0x01);
	crc8(&crc, 0x01);
	crc8(&crc, 0x08);
	crc8(&crc, 0x01);
	crc8(&crc, 0x08);
	crc8(&crc, 0x01);
	crc8(&crc, 0x08);

	/* Block 2 -- 0x08 - 0x0f */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x04);
	crc8(&crc, 0x00);

	/* Block 3 -- 0x00 - 0x07 */
	crc8(&crc, 0x03);
	crc8(&crc, 0x10);
	crc8(&crc, 0x03);
	crc8(&crc, 0x10);
	crc8(&crc, 0x02);
	crc8(&crc, 0x10);
	crc8(&crc, 0x02);
	crc8(&crc, 0x10);

	/* Block 3 -- 0x08 - 0x0f */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x11);
	crc8(&crc, 0x30);

	/* Append zeros of augmented message */
	crc8(&crc, 0x00);

	assertEqualInt (crc, 0x89);

    } while (0);
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
DEFINE_TEST(test_mad_crc8_real_example_1)
{
    do {
	/* Preset */
	uint8_t crc = CRC_PRESET;

	/* Block 1 -- 0x01 - 0x07 */
	crc8(&crc, 0x01);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);

	/* Block 2 -- 0x08 - 0x0f */
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Block 3 -- 0x00 - 0x07 */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Block 3 -- 0x08 - 0x0f */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Append zeros of augmented message */
	crc8(&crc, 0x00);

	assertEqualInt (crc, 0xc4);

    } while (0);
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
DEFINE_TEST(test_mad_crc8_real_example_2)
{
    do {
	/* Preset */
	uint8_t crc = CRC_PRESET;

	/* Block 1 -- 0x01 - 0x07 */
	crc8(&crc, 0x01);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);

	/* Block 2 -- 0x08 - 0x0f */
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x03);
	crc8(&crc, 0xe1);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Block 3 -- 0x00 - 0x07 */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Block 3 -- 0x08 - 0x0f */
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);
	crc8(&crc, 0x00);

	/* Append zeros of augmented message */
	crc8(&crc, 0x00);

	assertEqualInt (crc, 0xab);

    } while (0);
}

DEFINE_TEST (test_mad_sector_0x00_crc8)
{
    int res;

    do {
	Mad mad = mad_new (1);
	assert (mad != NULL);

	if (mad) {
	    res = mad_set_card_publisher_sector (mad, 0x01);

	    /* Block 1 */
	    MadAid aid1 = { 0x08, 0x01 };
	    mad_set_aid (mad, 1, aid1);
	    mad_set_aid (mad, 2, aid1);
	    mad_set_aid (mad, 3, aid1);

	    /* Block 2 */
	    MadAid empty_aid = { 0x00, 0x00 };
	    mad_set_aid (mad, 4, empty_aid);
	    mad_set_aid (mad, 5, empty_aid);
	    mad_set_aid (mad, 6, empty_aid);
	    MadAid aid2 = { 0x00, 0x04 };
	    mad_set_aid (mad, 7, aid2);

	    /* Block 3 */
	    MadAid aid3 = { 0x10, 0x03 };
	    mad_set_aid (mad, 8, aid3);
	    mad_set_aid (mad, 9, aid3);
	    MadAid aid4 = { 0x10, 0x02 };
	    mad_set_aid (mad, 10, aid4);
	    mad_set_aid (mad, 11, aid4);

	    mad_set_aid (mad, 12, empty_aid);
	    mad_set_aid (mad, 13, empty_aid);
	    mad_set_aid (mad, 14, empty_aid);
	    MadAid aid5 = { 0x30, 0x11 };
	    mad_set_aid (mad, 15, aid5);

	    res = sector_0x00_crc8 (mad);
	    assertEqualInt(0x89, res);
	}

	mad_free (mad);

    } while (0);
}
