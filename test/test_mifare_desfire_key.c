/*-
 * Copyright (C) 2010, Romain Tartiere.
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

#include <cutter.h>

#include <freefare.h>


void
test_mifare_desfire_key(void)
{
    MifareDESFireKey key;
    int version;

    uint8_t key1_des_data[8] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    key = mifare_desfire_des_key_new(key1_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_des_key_new_with_version(key1_des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x55, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
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


    uint8_t key1_3des_data[16] = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC, 0xDD, 0XEE, 0xFF };

    key = mifare_desfire_3des_key_new(key1_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key1_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x55, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_set_version(key, 0xaa);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0xaa, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    uint8_t key2_3des_data[16] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0X01, 0x00, 0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77 };

    key = mifare_desfire_3des_key_new(key2_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key2_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x02, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    uint8_t key3_3des_data[16] = { 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0X00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x77 };

    key = mifare_desfire_3des_key_new(key3_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x00, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);

    key = mifare_desfire_3des_key_new_with_version(key3_3des_data);
    version = mifare_desfire_key_get_version(key);
    cut_assert_equal_int(0x10, version, cut_message("Wrong MifareDESFireKey version"));
    mifare_desfire_key_free(key);
}
