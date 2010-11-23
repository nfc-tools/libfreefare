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

#include <freefare.h>

#include "mifare_desfire_auto_authenticate.h"

uint8_t key_data_null[8]  = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
uint8_t key_data_des[8]   = { 'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H' };
uint8_t key_data_3des[16] = { 'C', 'a', 'r', 'd', ' ', 'M', 'a', 's', 't', 'e', 'r', ' ', 'K', 'e', 'y', '!' };

void
mifare_desfire_auto_authenticate (MifareTag tag, uint8_t key_no)
{
    /* Determine which key is currently the master one */
    uint8_t key_version;
    int res = mifare_desfire_get_key_version (tag, key_no, &key_version);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_get_key_version()"));

    MifareDESFireKey key;

    switch (key_version) {
    case 0x00:
	key = mifare_desfire_des_key_new_with_version (key_data_null);
	break;
    case 0xAA:
	key = mifare_desfire_des_key_new_with_version (key_data_des);
	break;
    case 0xC7:
	key = mifare_desfire_3des_key_new_with_version (key_data_3des);
	break;
    default:
	cut_fail ("Unknown master key.");
    }

    cut_assert_not_null (key, cut_message ("Cannot allocate key"));

    /* Authenticate with this key */
    res = mifare_desfire_authenticate (tag, key_no, key);
    cut_assert_equal_int (0, res, cut_message ("mifare_desfire_authenticate()"));

    mifare_desfire_key_free (key);
}
