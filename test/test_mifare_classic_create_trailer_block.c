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

#include <cutter.h>

#include <freefare.h>

void
test_mifare_classic_create_trailer_block(void)
{
    MifareClassicBlock data;

    MifareClassicKey key_a = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    MifareClassicKey key_b = { 0xde, 0xad, 0xbe, 0xef, 0xff, 0xff };

    mifare_classic_trailer_block(&data, key_a, 0, 0, 0, 4, 0x42, key_b);

    cut_assert_equal_memory(data, sizeof(data), "\xff\xff\xff\xff\xff\xff\xff\x07\x80\x42\xde\xad\xbe\xef\xff\xff", sizeof(data), cut_message("Wrong generated block"));
}

