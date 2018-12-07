#include <cutter.h>
#include <freefare.h>
#include "freefare_internal.h"

void
test_mifare_rol(void)
{
    uint8_t data[8] = "01234567";
    rol(data, 8);
    cut_assert_equal_memory("12345670", 8, data, 8, cut_message("Wrong data"));

    uint8_t data2[16] = "0123456789abcdef";
    rol(data2, 16);
    cut_assert_equal_memory(data2, 16, "123456789abcdef0", 16, cut_message("Wrong data"));
}

void
test_mifare_desfire_des_receive(void)
{
    uint8_t null_ivect[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    uint8_t data[8]  = { 0xd6, 0x59, 0xe1, 0x70, 0x43, 0xa8, 0x40, 0x68 };
    uint8_t key_data[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version(key_data);

    uint8_t expected_data[8]  = { 0x73, 0x0d, 0xdf, 0xad, 0xa4, 0xd2, 0x07, 0x89 };
    uint8_t expected_key[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };

    mifare_cypher_blocks_chained(NULL, key, null_ivect, data, 8, MCD_RECEIVE, MCO_DECYPHER);

    cut_assert_equal_memory(&expected_data,  8, &data,       8, cut_message("Wrong data"));
    cut_assert_equal_memory(&expected_key,   8, key->data,   8, cut_message("Wrong key"));

    mifare_desfire_key_free(key);
}


void
test_mifare_desfire_des_send(void)
{
    uint8_t null_ivect[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    uint8_t data[8]  = { 0x73, 0x0d, 0xdf, 0xad, 0xa4, 0xd2, 0x07, 0x89 };
    uint8_t key_data[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };
    MifareDESFireKey key = mifare_desfire_des_key_new_with_version(key_data);

    uint8_t expected_data[8]  = { 0xd6, 0x59, 0xe1, 0x70, 0x43, 0xa8, 0x40, 0x68 };
    uint8_t expected_key[8]   = { 1, 1, 1, 1, 1, 1, 1, 1 };

    mifare_cypher_blocks_chained(NULL, key, null_ivect, data, 8, MCD_SEND, MCO_DECYPHER);

    cut_assert_equal_memory(&expected_data,  8, &data,       8, cut_message("Wrong data"));
    cut_assert_equal_memory(&expected_key,   8, key->data,   8, cut_message("Wrong key"));

    mifare_desfire_key_free(key);
}

void
test_mifare_desfire_padded_data_length(void)
{
    size_t res;

    res = padded_data_length(0, 8);
    cut_assert_equal_int(res, 8, cut_message("Invalid size"));
    res = padded_data_length(1, 8);
    cut_assert_equal_int(res, 8, cut_message("Invalid size"));
    res = padded_data_length(8, 8);
    cut_assert_equal_int(res, 8, cut_message("Invalid size"));
    res = padded_data_length(9, 8);
    cut_assert_equal_int(res, 16, cut_message("Invalid size"));
    res = padded_data_length(0, 16);
    cut_assert_equal_int(res, 16, cut_message("Invalid size"));
    res = padded_data_length(33, 16);
    cut_assert_equal_int(res, 48, cut_message("Invalid size"));
}
