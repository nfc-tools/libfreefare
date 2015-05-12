/*-
 * Copyright (C) 2010, Romain Tartiere, Romuald Conty.
 * 
 * This program is free software: you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by the
 * Free Software Foundation, either version 3 of the License, or (at your
 * option) any later version.
 * 
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>
 */

/*
 * These tests implement examples provided in the following documents:
 *
 * NIST Special Publication 800-38B
 * Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
 * May 2005
 */

#include <cutter.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

uint8_t key_data[] = {
    0x2b, 0x7e, 0x15, 0x16,
    0x28, 0xae, 0xd2, 0xa6,
    0xab, 0xf7, 0x15, 0x88,
    0x09, 0xcf, 0x4f, 0x3c
};


void
test_mifare_desfire_aes_generate_subkeys (void)
{
    uint8_t sk1[] = {
	0xfb, 0xee, 0xd6, 0x18,
	0x35, 0x71, 0x33, 0x66,
	0x7c, 0x85, 0xe0, 0x8f,
	0x72, 0x36, 0xa8, 0xde
    };

    uint8_t sk2[] = {
	0xf7, 0xdd, 0xac, 0x30,
	0x6a, 0xe2, 0x66, 0xcc,
	0xf9, 0x0b, 0xc1, 0x1e,
	0xe4, 0x6d, 0x51, 0x3b
    };

    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
    cmac_generate_subkeys (key);

    cut_assert_equal_memory (sk1, 16, key->cmac_sk1, 16, cut_message ("Wrong sub-key 1"));
    cut_assert_equal_memory (sk2, 16, key->cmac_sk2, 16, cut_message ("Wrong sub-key 2"));

    mifare_desfire_key_free (key);
}

void
test_mifare_desfire_aes_cmac_empty (void)
{
    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
    cmac_generate_subkeys (key);

    uint8_t ivect[16];
    memset (ivect, 0, sizeof (ivect));

    uint8_t expected_cmac[] = {
	0xbb, 0x1d, 0x69, 0x29,
	0xe9, 0x59, 0x37, 0x28,
	0x7f, 0xa3, 0x7d, 0x12,
	0x9b, 0x75, 0x67, 0x46
    };

    uint8_t my_cmac[16];
    cmac (key, ivect, NULL, 0, my_cmac);

    cut_assert_equal_memory (expected_cmac, 16, my_cmac, 16, cut_message ("Wrong CMAC"));

    mifare_desfire_key_free (key);
}

void
test_mifare_desfire_aes_cmac_128 (void)
{
    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
    cmac_generate_subkeys (key);

    uint8_t ivect[16];
    memset (ivect, 0, sizeof (ivect));

    uint8_t message[] = {
	0x6b, 0xc1, 0xbe, 0xe2,
	0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11,
	0x73, 0x93, 0x17, 0x2a
    };

    uint8_t expected_cmac[] = {
	0x07, 0x0a, 0x16, 0xb4,
	0x6b, 0x4d, 0x41, 0x44,
	0xf7, 0x9b, 0xdd, 0x9d,
	0xd0, 0x4a, 0x28, 0x7c
    };

    uint8_t my_cmac[16];
    cmac (key, ivect, message, 16, my_cmac);

    cut_assert_equal_memory (expected_cmac, 16, my_cmac, sizeof (message), cut_message ("Wrong CMAC"));

    mifare_desfire_key_free (key);
}

void
test_mifare_desfire_aes_cmac_320 (void)
{
    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
    cmac_generate_subkeys (key);

    uint8_t ivect[16];
    memset (ivect, 0, sizeof (ivect));

    uint8_t message[] = {
	0x6b, 0xc1, 0xbe, 0xe2,
	0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11,
	0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57,
	0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac,
	0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46,
	0xa3, 0x5c, 0xe4, 0x11
    };

    uint8_t expected_cmac[] = {
	0xdf, 0xa6, 0x67, 0x47,
	0xde, 0x9a, 0xe6, 0x30,
	0x30, 0xca, 0x32, 0x61,
	0x14, 0x97, 0xc8, 0x27
    };

    uint8_t my_cmac[16];
    cmac (key, ivect, message, sizeof (message), my_cmac);

    cut_assert_equal_memory (expected_cmac, 16, my_cmac, 16, cut_message ("Wrong CMAC"));

    mifare_desfire_key_free (key);
}

void
test_mifare_desfire_aes_cmac_512 (void)
{
    MifareDESFireKey key = mifare_desfire_aes_key_new (key_data);
    cmac_generate_subkeys (key);

    uint8_t ivect[16];
    memset (ivect, 0, sizeof (ivect));

    uint8_t message[] = {
	0x6b, 0xc1, 0xbe, 0xe2,
	0x2e, 0x40, 0x9f, 0x96,
	0xe9, 0x3d, 0x7e, 0x11,
	0x73, 0x93, 0x17, 0x2a,
	0xae, 0x2d, 0x8a, 0x57,
	0x1e, 0x03, 0xac, 0x9c,
	0x9e, 0xb7, 0x6f, 0xac,
	0x45, 0xaf, 0x8e, 0x51,
	0x30, 0xc8, 0x1c, 0x46,
	0xa3, 0x5c, 0xe4, 0x11,
	0xe5, 0xfb, 0xc1, 0x19,
	0x1a, 0x0a, 0x52, 0xef,
	0xf6, 0x9f, 0x24, 0x45,
	0xdf, 0x4f, 0x9b, 0x17,
	0xad, 0x2b, 0x41, 0x7b,
	0xe6, 0x6c, 0x37, 0x10
    };

    uint8_t expected_cmac[] = {
	0x51, 0xf0, 0xbe, 0xbf,
	0x7e, 0x3b, 0x9d, 0x92,
	0xfc, 0x49, 0x74, 0x17,
	0x79, 0x36, 0x3c, 0xfe
    };

    uint8_t my_cmac[16];
    cmac (key, ivect, message, sizeof (message), my_cmac);

    cut_assert_equal_memory (expected_cmac, 16, my_cmac, 16, cut_message ("Wrong CMAC"));

    mifare_desfire_key_free (key);
}
