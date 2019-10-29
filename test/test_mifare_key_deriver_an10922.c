#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

void
test_mifare_key_deriver_an10922_aes128(void)
{
    MifareDESFireKey key = NULL;
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = NULL;
    int version, ret;

    // These test vectors come from NCP's AN10922, section 2.2.1
    uint8_t key1_aes128_data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0XEE, 0xFF };
    uint8_t key1_aes128_version = 16;
    uint8_t key1_aes128_derived_data[16] = { 0xA8, 0xDD, 0x63, 0xA3, 0xB8, 0x9D, 0x54, 0xB3, 0x7C, 0xA8, 0x02, 0x47, 0x3F, 0xDA, 0x91, 0x75 };
    uint8_t key1_aes128_check_m[] = { 0x01, 0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41, 0x62, 0x75 };

    key = mifare_desfire_aes_key_new_with_version(key1_aes128_data, key1_aes128_version);

    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong master key version"));

    deriver = mifare_key_deriver_new_an10922(key, MIFARE_KEY_AES128, AN10922_FLAG_DEFAULT);

    ret = mifare_key_deriver_begin(deriver);
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_begin failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x04\x78\x2E\x21\x80\x1D\x80");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x30\x42\xF5");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "NXP Abu");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    derived_key = mifare_key_deriver_end(deriver);
    cut_assert_not_null(derived_key, cut_message("mifare_key_deriver_end failed"));

    cut_assert_equal_memory(key1_aes128_check_m, sizeof(key1_aes128_check_m), deriver->m, deriver->len, cut_message("Wrong CMAC message"));

    version = mifare_desfire_key_get_version(derived_key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong derived key version"));

    cut_assert_equal_int(derived_key->type, MIFARE_KEY_AES128, cut_message("Wrong derived key type"));

    cut_assert_equal_memory(key1_aes128_derived_data, sizeof(key1_aes128_derived_data), derived_key->data, sizeof(key1_aes128_derived_data), cut_message("Wrong derived key"));
    mifare_key_deriver_free(deriver);
    mifare_desfire_key_free(derived_key);
    mifare_desfire_key_free(key);
}

void
test_mifare_key_deriver_an10922_aes128_short_m(void)
{
    MifareDESFireKey key = NULL;
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = NULL;
    int version, ret;

    // These test vectors came from AN10957, pages 13-14
    uint8_t key1_aes128_data[16] = { 0xf3, 0xf9, 0x37, 0x76, 0x98, 0x70, 0x7b, 0x68, 0x8e, 0xaf, 0x84, 0xab, 0xe3, 0x9e, 0x37, 0x91 };
    uint8_t key1_aes128_version = 16;
    uint8_t key1_aes128_derived_data[16] = { 0x0b, 0xb4, 0x08, 0xba, 0xff, 0x98, 0xb6, 0xee, 0x9f, 0x2e, 0x15, 0x85, 0x77, 0x7f, 0x6a, 0x51 };
    uint8_t key1_aes128_check_m[] = { 0x01, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed };

    key = mifare_desfire_aes_key_new_with_version(key1_aes128_data, key1_aes128_version);

    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong master key version"));

    deriver = mifare_key_deriver_new_an10922(key, MIFARE_KEY_AES128, AN10922_FLAG_DEFAULT);

    ret = mifare_key_deriver_begin(deriver);
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_begin failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x04\xde\xad\xbe\xef\xfe\xed");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    derived_key = mifare_key_deriver_end(deriver);
    cut_assert_not_null(derived_key, cut_message("mifare_key_deriver_end failed"));

    cut_assert_equal_memory(key1_aes128_check_m, sizeof(key1_aes128_check_m), deriver->m, deriver->len, cut_message("Wrong CMAC message"));

    version = mifare_desfire_key_get_version(derived_key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong derived key version"));

    cut_assert_equal_int(derived_key->type, MIFARE_KEY_AES128, cut_message("Wrong derived key type"));

    cut_assert_equal_memory(key1_aes128_derived_data, sizeof(key1_aes128_derived_data), derived_key->data, sizeof(key1_aes128_derived_data), cut_message("Wrong derived key"));
    mifare_key_deriver_free(deriver);
    mifare_desfire_key_free(derived_key);
    mifare_desfire_key_free(key);
}

void
test_mifare_key_deriver_an10922_aes128_issue_91(void)
{
    MifareDESFireKey key = NULL;
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = NULL;
    int version, ret;

    // These test vectors came from AN10957, pages 13-14; EXCEPT that the derived
    // data reflects the use of the AN10922_FLAG_EMULATE_ISSUE_91 flag.
    uint8_t key1_aes128_data[16] = { 0xf3, 0xf9, 0x37, 0x76, 0x98, 0x70, 0x7b, 0x68, 0x8e, 0xaf, 0x84, 0xab, 0xe3, 0x9e, 0x37, 0x91 };
    uint8_t key1_aes128_version = 16;
    uint8_t key1_aes128_derived_data[16] = { 0x72, 0x1e, 0x2c, 0x01, 0xe8, 0x1a, 0xf8, 0x5d, 0x81, 0x56, 0x33, 0x96, 0x9c, 0xea, 0x26, 0x07 };
    uint8_t key1_aes128_check_m[] = { 0x01, 0x04, 0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed };

    key = mifare_desfire_aes_key_new_with_version(key1_aes128_data, key1_aes128_version);

    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong master key version"));

    deriver = mifare_key_deriver_new_an10922(key, MIFARE_KEY_AES128, AN10922_FLAG_EMULATE_ISSUE_91);

    ret = mifare_key_deriver_begin(deriver);
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_begin failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x04\xde\xad\xbe\xef\xfe\xed");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    derived_key = mifare_key_deriver_end(deriver);
    cut_assert_not_null(derived_key, cut_message("mifare_key_deriver_end failed"));

    cut_assert_equal_memory(key1_aes128_check_m, sizeof(key1_aes128_check_m), deriver->m, deriver->len, cut_message("Wrong CMAC message"));

    version = mifare_desfire_key_get_version(derived_key);
    cut_assert_equal_int(key1_aes128_version, version, cut_message("Wrong derived key version"));

    cut_assert_equal_int(derived_key->type, MIFARE_KEY_AES128, cut_message("Wrong derived key type"));

    cut_assert_equal_memory(key1_aes128_derived_data, sizeof(key1_aes128_derived_data), derived_key->data, sizeof(key1_aes128_derived_data), cut_message("Wrong derived key"));
    mifare_key_deriver_free(deriver);
    mifare_desfire_key_free(derived_key);
    mifare_desfire_key_free(key);
}

void
test_mifare_key_deriver_an10922_2k3des(void)
{
    MifareDESFireKey key = NULL;
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = NULL;
    int version, ret;

    // These test vectors come from NCP's AN10922, section 2.4.1
    uint8_t key1_2k3des_data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0XEE, 0xFF };
    uint8_t key1_2k3des_derived_data[16] = { 0x16, 0xf9, 0x58, 0x7d, 0x9e, 0x89, 0x10, 0xc9, 0x6b, 0x96, 0x49, 0xd0, 0x07, 0x10, 0x7d, 0xd6 };
    uint8_t key1_2k3des_check_m[] = { 0x22, 0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50, 0x20, 0x41 };

    key = mifare_desfire_3des_key_new_with_version(key1_2k3des_data);

    deriver = mifare_key_deriver_new_an10922(key, MIFARE_KEY_2K3DES, AN10922_FLAG_DEFAULT);

    ret = mifare_key_deriver_begin(deriver);
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_begin failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x04\x78\x2E\x21\x80\x1D\x80");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x30\x42\xF5");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "NXP A");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    derived_key = mifare_key_deriver_end(deriver);
    cut_assert_not_null(derived_key, cut_message("mifare_key_deriver_end failed"));

    cut_assert_equal_memory(key1_2k3des_check_m, sizeof(key1_2k3des_check_m), deriver->m, deriver->len, cut_message("Wrong CMAC message"));

    version = mifare_desfire_key_get_version(derived_key);
    cut_assert_equal_int(mifare_desfire_key_get_version(key), version, cut_message("Wrong derived key version"));

    cut_assert_equal_int(derived_key->type, MIFARE_KEY_2K3DES, cut_message("Wrong derived key type"));

    cut_assert_equal_memory(key1_2k3des_derived_data, sizeof(key1_2k3des_derived_data), derived_key->data, sizeof(key1_2k3des_derived_data), cut_message("Wrong derived key"));
    mifare_key_deriver_free(deriver);
    mifare_desfire_key_free(derived_key);
    mifare_desfire_key_free(key);
}

void
test_mifare_key_deriver_an10922_3k3des(void)
{
    MifareDESFireKey key = NULL;
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = NULL;
    int version, ret;

    // These test vectors come from NCP's AN10922, section 2.5.1
    uint8_t key1_3k3des_data[24] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0XEE, 0xFF, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    uint8_t key1_3k3des_derived_data[24] = { 0x2E, 0x0D, 0xD0, 0x37, 0x74, 0xD3, 0xFA, 0x9B, 0x57, 0x05, 0xAB, 0x0B, 0xDA, 0x91, 0xCA, 0x0B, 0x55, 0xB8, 0xE0, 0x7F, 0xCD, 0xBF, 0x10, 0xEC };
    uint8_t key1_3k3des_check_m[] = { 0x33, 0x04, 0x78, 0x2E, 0x21, 0x80, 0x1D, 0x80, 0x30, 0x42, 0xF5, 0x4E, 0x58, 0x50 };

    key = mifare_desfire_3k3des_key_new_with_version(key1_3k3des_data);

    deriver = mifare_key_deriver_new_an10922(key, MIFARE_KEY_3K3DES, AN10922_FLAG_DEFAULT);

    ret = mifare_key_deriver_begin(deriver);
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_begin failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x04\x78\x2E\x21\x80\x1D\x80");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "\x30\x42\xF5");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    ret = mifare_key_deriver_update_cstr(deriver, "NXP");
    cut_assert_equal_int(ret, 0, cut_message("mifare_key_deriver_update failed"));

    derived_key = mifare_key_deriver_end(deriver);
    cut_assert_not_null(derived_key, cut_message("mifare_key_deriver_end failed"));

    cut_assert_equal_memory(key1_3k3des_check_m, sizeof(key1_3k3des_check_m), deriver->m, deriver->len, cut_message("Wrong CMAC message"));

    version = mifare_desfire_key_get_version(derived_key);
    cut_assert_equal_int(mifare_desfire_key_get_version(key), version, cut_message("Wrong derived key version"));

    cut_assert_equal_int(derived_key->type, MIFARE_KEY_3K3DES, cut_message("Wrong derived key type"));

    cut_assert_equal_memory(key1_3k3des_derived_data, sizeof(key1_3k3des_derived_data), derived_key->data, sizeof(key1_3k3des_derived_data), cut_message("Wrong derived key"));
    mifare_key_deriver_free(deriver);
    mifare_desfire_key_free(derived_key);
    mifare_desfire_key_free(key);
}
