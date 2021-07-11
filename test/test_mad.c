#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

static void
nxp_crc_bitwise(uint8_t *crc, const uint8_t value)
{
    const uint8_t poly = 0x1d;

    *crc ^= value;
    for (int current_bit = 7; current_bit >= 0; current_bit--) {
        int bit_out = (*crc) & 0x80;
        *crc <<= 1;
        if (bit_out)
            *crc ^= poly;
    }
}

static void
nxp_crc_wrapper(uint8_t *crc, const uint8_t value)
{
    uint8_t res_bitwise = *crc;
    nxp_crc_bitwise(&res_bitwise, value);
    nxp_crc(crc, value);
    cut_assert_equal_uint(*crc, res_bitwise, cut_message("Bitwise and bytewise CRC calculation result not equal!"));
}

void
test_mad(void)
{
    int res;

    Mad mad = mad_new(1);
    cut_assert_not_null(mad, cut_message("Can create a new MAD"));

    cut_assert_equal_int(1, mad_get_version(mad), cut_message("Wrong default MAD version"));
    mad_set_version(mad, 2);
    cut_assert_equal_int(2, mad_get_version(mad), cut_message("Can't change MAD version"));

    cut_assert_equal_int(0, mad_get_card_publisher_sector(mad), cut_message("Wrong default MAD publisher"));

    res = mad_set_card_publisher_sector(mad, 13);
    cut_assert_equal_int(0, res, cut_message("mad_set_card_publisher_sector() returned an error."));
    cut_assert_equal_int(13, mad_get_card_publisher_sector(mad), cut_message("Wrong publisher sector"));

    res = mad_set_card_publisher_sector(mad, 0xff);
    cut_assert_equal_int(-1, res, cut_message("Invalid sector"));
    cut_assert_equal_int(13, mad_get_card_publisher_sector(mad), cut_message("Previous publisher sector value"));

    MadAid aid = {
	.function_cluster_code = 0,
	.application_code = 0
    };

    res = mad_get_aid(mad, 3, &aid);
    cut_assert_equal_int(0, res, cut_message("mad_get_aid() failed"));
    cut_assert_equal_int(0, aid.function_cluster_code, cut_message("Invalid default value"));
    cut_assert_equal_int(0, aid.application_code, cut_message("Invalid default value"));

    aid.function_cluster_code = 0xc0;
    aid.application_code = 0x42;
    res = mad_set_aid(mad, 3, aid);
    cut_assert_equal_int(0, res, cut_message("mad_set_aid() failed"));

    res = mad_get_aid(mad, 3, &aid);
    cut_assert_equal_int(0, res, cut_message("mad_get_aid() failed"));
    cut_assert_equal_int(0xC0, aid.function_cluster_code, cut_message("Invalid value"));
    cut_assert_equal_int(0x42, aid.application_code, cut_message("Invalid value"));

    mad_free(mad);
}

#define CRC_PRESET 0xc7

void
test_mad_crc8_basic(void)
{
    uint8_t crc;
    const uint8_t crc_value = 0x42;

    /* Check integrity */
    crc = CRC_PRESET;
    nxp_crc_wrapper(&crc, crc_value);
    uint8_t save = crc;

    crc = CRC_PRESET;
    nxp_crc_wrapper(&crc, crc_value);
    nxp_crc_wrapper(&crc, save);
    cut_assert_equal_int(0x00, crc, cut_message("CRC should verify crc(message + crc(message)) = 0"));
}

/*
 * The following MAD values where extracted from documentation.
 */
void
test_mad_crc8_doc_example(void)
{
    /* Preset */
    uint8_t crc = CRC_PRESET;

    /* Block 1 -- 0x01 - 0x07 */
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x08);
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x08);
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x08);

    /* Block 2 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x04);
    nxp_crc_wrapper(&crc, 0x00);

    /* Block 3 -- 0x00 - 0x07 */
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0x10);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0x10);
    nxp_crc_wrapper(&crc, 0x02);
    nxp_crc_wrapper(&crc, 0x10);
    nxp_crc_wrapper(&crc, 0x02);
    nxp_crc_wrapper(&crc, 0x10);

    /* Block 3 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x11);
    nxp_crc_wrapper(&crc, 0x30);

    /* Append zeros of augmented message */

    cut_assert_equal_int(0x89, crc, cut_message("Sample CRC should match"));
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
void
test_mad_crc8_real_example_1(void)
{
    /* Preset */
    uint8_t crc = CRC_PRESET;

    /* Block 1 -- 0x01 - 0x07 */
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);

    /* Block 2 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Block 3 -- 0x00 - 0x07 */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Block 3 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Append zeros of augmented message */

    cut_assert_equal_int(0xc4, crc, cut_message("Read example 1 CRC should match"));
}

/*
 * The following MAD values where extracted from a MIFARE dump.
 */
void
test_mad_crc8_real_example_2(void)
{
    /* Preset */
    uint8_t crc = CRC_PRESET;

    /* Block 1 -- 0x01 - 0x07 */
    nxp_crc_wrapper(&crc, 0x01);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);

    /* Block 2 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x03);
    nxp_crc_wrapper(&crc, 0xe1);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Block 3 -- 0x00 - 0x07 */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Block 3 -- 0x08 - 0x0f */
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);
    nxp_crc_wrapper(&crc, 0x00);

    /* Append zeros of augmented message */

    cut_assert_equal_int(0xab, crc, cut_message("Read example 1 CRC should match"));
}

void
test_mad_sector_0x00_crc8(void)
{
    int res;
    Mad mad = mad_new(1);
    cut_assert_not_null(mad, cut_message("mad_new() failed"));

    res = mad_set_card_publisher_sector(mad, 0x01);

    /* Block 1 */
    MadAid aid1 = { 0x01, 0x08 };
    mad_set_aid(mad, 1, aid1);
    mad_set_aid(mad, 2, aid1);
    mad_set_aid(mad, 3, aid1);

    /* Block 2 */
    MadAid empty_aid = { 0x00, 0x00 };
    mad_set_aid(mad, 4, empty_aid);
    mad_set_aid(mad, 5, empty_aid);
    mad_set_aid(mad, 6, empty_aid);
    MadAid aid2 = { 0x04, 0x00 };
    mad_set_aid(mad, 7, aid2);

    /* Block 3 */
    MadAid aid3 = { 0x03, 0x10 };
    mad_set_aid(mad, 8, aid3);
    mad_set_aid(mad, 9, aid3);
    MadAid aid4 = { 0x02, 0x10 };
    mad_set_aid(mad, 10, aid4);
    mad_set_aid(mad, 11, aid4);

    mad_set_aid(mad, 12, empty_aid);
    mad_set_aid(mad, 13, empty_aid);
    mad_set_aid(mad, 14, empty_aid);
    MadAid aid5 = { 0x11, 0x30 };
    mad_set_aid(mad, 15, aid5);

    res = sector_0x00_crc8(mad);
    cut_assert_equal_int(0x89, res, cut_message("Sample CRC should match"));

    mad_free(mad);
}
