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
 * 
 * $Id$
 */

#include <cutter.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <freefare.h>
#include "freefare_internal.h"

#include "mifare_desfire_ev1_fixture.h"
#include "common/mifare_desfire_auto_authenticate.h"

#define cut_assert_success(last_command) \
    do { \
	cut_assert_equal_int (OPERATION_OK, mifare_desfire_last_picc_error (tag), cut_message ("PICC replied %s", mifare_desfire_error_lookup (mifare_desfire_last_picc_error (tag)))); \
	cut_assert_not_equal_int (-1, res, cut_message ("Wrong return value")); \
    } while (0)

void
test_mifare_desfire_ev1_aes2 (void)
{
    int res;
    MifareDESFireKey  key;

    mifare_desfire_auto_authenticate (tag, 0);

    // Setup the AES key
    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
    res = mifare_desfire_change_key (tag, 0x80, key, NULL);
    cut_assert_success ("mifare_desfire_change_key");
    mifare_desfire_key_free (key);

    // Authenticate with the AES key
    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
    res = mifare_desfire_authenticate_aes (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate");
    mifare_desfire_key_free (key);

    res = mifare_desfire_format_picc (tag);
    cut_assert_success ("mifare_desfire_format_picc()");

    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
    res = mifare_desfire_authenticate_aes (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate");
    mifare_desfire_key_free (key);

    uint32_t size;
    res = mifare_desfire_free_mem (tag, &size);
    cut_assert_success ("mifare_desfire_free_mem");

    // Do some commands to check CMAC is properly handled
    res = mifare_desfire_free_mem (tag, &size);
    cut_assert_success ("mifare_desfire_free_mem");

    struct mifare_desfire_version_info info;
    res = mifare_desfire_get_version (tag, &info);
    cut_assert_success ("mifare_desfire_get_version");

    res = mifare_desfire_change_key_settings (tag, 0x0F);
    cut_assert_success ("mifare_desfire_change_key_settings");

    res = mifare_desfire_free_mem (tag, &size);
    cut_assert_success ("mifare_desfire_free_mem");

    MifareDESFireAID aid = mifare_desfire_aid_new (0x112233);

    mifare_desfire_delete_application (tag, aid);

    res = mifare_desfire_create_application (tag, aid, 0xff, 0x81);
    cut_assert_success ("mifare_desfire_create_application");

    res = mifare_desfire_select_application (tag, aid);
    cut_assert_success ("mifare_desfire_select_application");

    key = mifare_desfire_aes_key_new (key_data_aes);
    res = mifare_desfire_authenticate_aes (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate");
    free (key);

    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
    res = mifare_desfire_change_key (tag, 0x00, key, NULL);
    cut_assert_success ("mifare_desfire_change_key");
    mifare_desfire_key_free (key);

    key = mifare_desfire_aes_key_new (key_data_aes);
    res = mifare_desfire_authenticate_aes (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate");
    free (key);

    res = mifare_desfire_create_std_data_file (tag, 1, MDCM_MACED, 0x0000, 512);
    if ((mifare_desfire_last_picc_error (tag) != DUPLICATE_ERROR) && (mifare_desfire_last_picc_error(tag) != OPERATION_OK))
	cut_assert_success ("mifare_desfire_create_std_data_file");

    char sample_data[] = "Hello World!  I'm a string that is probably too long "
	"to feet in a single frame.  For this reason, it will be split and like"
	"ly, some failure in the algorirthm should trigger an error in this uni"
	"t test.";
    res = mifare_desfire_write_data_ex (tag, 1, 0, strlen (sample_data), sample_data, MDCM_MACED);
    cut_assert_success ("mifare_desfire_write_data");

    char buffer[1024];

    res = mifare_desfire_read_data_ex (tag, 1, 0, 27, buffer, MDCM_MACED);
    cut_assert_success ("mifare_desfire_read_data");
    cut_assert_equal_memory (buffer, res, sample_data, 27, cut_message ("AES crypto failed"));

    char canaries[] = "Canaries Canaries Canaries Canaries Canaries";

    res = mifare_desfire_read_data_ex (tag, 1, 0, 1, canaries, MDCM_MACED);
    cut_assert_success ("mifare_desfire_read_data");
    cut_assert_equal_int (1, res, cut_message ("Reading 1 byte should return 1 byte"));
    cut_assert_equal_memory (canaries, 44, "Hanaries Canaries Canaries Canaries Canaries", 44, cut_message ("Canaries got smashed!"));

    uint8_t s, c;
    res = mifare_desfire_get_key_settings (tag, &s, &c);
    cut_assert_success ("mifare_desfire_get__key_settings");

    res = mifare_desfire_read_data_ex (tag, 1, 27, 27, buffer, MDCM_MACED);
    cut_assert_success ("mifare_desfire_read_data");
    cut_assert_equal_memory (buffer, res, sample_data + 27, 27, cut_message ("AES crypto failed"));

    res = mifare_desfire_read_data_ex (tag, 1, 0, 0, buffer, MDCM_MACED);
    cut_assert_success ("mifare_desfire_read_data");
    cut_assert_equal_memory (buffer, strlen (buffer), sample_data, strlen (sample_data), cut_message ("AES crypto failed"));

    // Revert to the default DES key
    res = mifare_desfire_select_application (tag, NULL);
    cut_assert_success ("mifare_desfire_select_application");

    key = mifare_desfire_aes_key_new_with_version (key_data_aes, key_data_aes_version);
    res = mifare_desfire_authenticate_aes (tag, 0, key);
    cut_assert_success ("mifare_desfire_authenticate");
    mifare_desfire_key_free (key);

    key = mifare_desfire_des_key_new (key_data_null);
    res = mifare_desfire_change_key (tag, 0x00, key, NULL);
    cut_assert_success ("mifare_desfire_change_key");
    mifare_desfire_key_free (key);
}
