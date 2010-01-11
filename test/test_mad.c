#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

void
test_mad (void)
{
    int res;

    Mad mad = mad_new (1);
    cut_assert_not_null (mad);

    cut_assert_equal_int (1, mad_get_version (mad));
    mad_set_version (mad, 2);
    cut_assert_equal_int (2, mad_get_version (mad));

    cut_assert_equal_int (0, mad_get_card_publisher_sector (mad));

    res = mad_set_card_publisher_sector (mad, 13);
    cut_assert_equal_int (res, 0);
    cut_assert_equal_int (13, mad_get_card_publisher_sector (mad));

    res = mad_set_card_publisher_sector (mad, 0xff);
    cut_assert_equal_int (res, -1);
    cut_assert_equal_int (13, mad_get_card_publisher_sector (mad));

    MadAid aid = {
	.function_cluster_code = 0,
	.application_code = 0
    };

    res = mad_get_aid (mad, 3, &aid);
    cut_assert_equal_int (0, res);
    cut_assert_equal_int (0, aid.function_cluster_code);
    cut_assert_equal_int (0, aid.application_code);

    aid.function_cluster_code = 0xc0;
    aid.application_code = 0x42;
    res = mad_set_aid (mad, 3, aid);
    cut_assert_equal_int (0, res);

    res = mad_get_aid (mad, 3, &aid);
    cut_assert_equal_int (0, res);
    cut_assert_equal_int (0xC0, aid.function_cluster_code);
    cut_assert_equal_int (0x42, aid.application_code);

    mad_free (mad);
}

#define CRC_PRESET 0x67

void
test_mad_crc8_basic (void)
{
    uint8_t crc;
    const uint8_t crc_value = 0x42;

    /* Insert data */
    crc = 0x00;
    crc8(&crc, crc_value);
    cut_assert_equal_int (crc_value, crc);

    /* Insert data with leading zeros */
    crc = 0x00;
    crc8(&crc, 0x00);
    crc8(&crc, 0x00);
    crc8(&crc, 0x00);
    crc8(&crc, 0x00);
    crc8(&crc, 0x00);
    crc8(&crc, crc_value);
    cut_assert_equal_int (crc_value, crc);

    /* Check integrity */
    crc = CRC_PRESET;
    crc8(&crc, crc_value);
    crc8(&crc, 0x00);
    uint8_t save = crc;

    crc = CRC_PRESET;
    crc8(&crc, crc_value);
    crc8(&crc, save);
    cut_assert_equal_int (0x00, crc);
}

/*
 * The following MAD values where extracted from documentation.
 */
void
test_mad_crc8_doc_example (void)
{
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

    cut_assert_equal_int (0x89, crc);
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
void
test_mad_crc8_real_example_1 (void)
{
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

    cut_assert_equal_int (0xc4, crc);
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
void
test_mad_crc8_real_example_2 (void)
{
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

    cut_assert_equal_int (0xab, crc);
}

void
test_mad_sector_0x00_crc8 (void)
{
    int res;
    Mad mad = mad_new (1);
    cut_assert_not_null (mad);

    res = mad_set_card_publisher_sector (mad, 0x01);

    /* Block 1 */
    MadAid aid1 = { 0x01, 0x08 };
    mad_set_aid (mad, 1, aid1);
    mad_set_aid (mad, 2, aid1);
    mad_set_aid (mad, 3, aid1);

    /* Block 2 */
    MadAid empty_aid = { 0x00, 0x00 };
    mad_set_aid (mad, 4, empty_aid);
    mad_set_aid (mad, 5, empty_aid);
    mad_set_aid (mad, 6, empty_aid);
    MadAid aid2 = { 0x04, 0x00 };
    mad_set_aid (mad, 7, aid2);

    /* Block 3 */
    MadAid aid3 = { 0x03, 0x10 };
    mad_set_aid (mad, 8, aid3);
    mad_set_aid (mad, 9, aid3);
    MadAid aid4 = { 0x02, 0x10 };
    mad_set_aid (mad, 10, aid4);
    mad_set_aid (mad, 11, aid4);

    mad_set_aid (mad, 12, empty_aid);
    mad_set_aid (mad, 13, empty_aid);
    mad_set_aid (mad, 14, empty_aid);
    MadAid aid5 = { 0x11, 0x30 };
    mad_set_aid (mad, 15, aid5);

    res = sector_0x00_crc8 (mad);
    cut_assert_equal_int(0x89, res);

    mad_free (mad);
}
