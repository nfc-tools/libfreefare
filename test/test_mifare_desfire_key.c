#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"


void
test_mifare_desfire_key(void)
{
    MifareDESFireKey key;
    int version;

    uint8_t key1_des_data[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    key = mifare_desfire_des_key_new(key1_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_des_data, sizeof(key1_des_data), key->data, sizeof(key1_des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_des_key_new_with_version(key1_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x55, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_des_data, sizeof(key1_des_data), key->data, sizeof(key1_des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);


    uint8_t key2_des_data[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    key = mifare_desfire_des_key_new(key2_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_des_key_new_with_version(key2_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);


    uint8_t key1_3des_data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x89, 0x98, 0xAB, 0xBA, 0xCD, 0xDC, 0xEF, 0xFE };

    key = mifare_desfire_3des_key_new(key1_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_3des_data, sizeof(key1_3des_data), key->data, sizeof(key1_3des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key1_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x55, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_3des_data, sizeof(key1_3des_data), key->data, sizeof(key1_3des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);

    uint8_t key2_3des_data[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    key = mifare_desfire_3des_key_new(key2_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key2_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x02, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    uint8_t key3_3des_data[16] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77 };

    key = mifare_desfire_3des_key_new(key3_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key3_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x10, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    uint8_t key1_3k3des_data[24] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };

    key = mifare_desfire_3k3des_key_new(key1_3k3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_3k3des_data, sizeof(key1_3k3des_data), key->data, sizeof(key1_3k3des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3k3des_key_new_with_version(key1_3k3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x55, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_3k3des_data, sizeof(key1_3k3des_data), key->data, sizeof(key1_3k3des_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);


    uint8_t key1_aes_data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF };

    key = mifare_desfire_aes_key_new(key1_aes_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x55);
    cut_assert_equal_memory(key1_aes_data, sizeof(key1_aes_data), key->data, sizeof(key1_aes_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_aes_key_new_with_version(key1_aes_data, 0x33);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x33, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0x33);
    cut_assert_equal_memory(key1_aes_data, sizeof(key1_aes_data), key->data, sizeof(key1_aes_data), cut_message("Version change corrupted key"));
    mifare_desfire_key_free(key);
}
