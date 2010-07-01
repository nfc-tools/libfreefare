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
 * 
 * $Id$
 */

#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

void
test_mifare_classic_sector_boundaries (void)
{
    for (int i=0; i < 32; i++) {
	for (int j=0; j < 4; j++) {
	    cut_assert_equal_int (4 * i, mifare_classic_first_sector_block (4 * i), cut_message ("Wrong first block number for block %d", i));
	    cut_assert_equal_int (4 * i + 3, mifare_classic_last_sector_block (4 * i + j), cut_message ("Wrong last block number for block %d", i));
	}
    }

    for (int i=0; i < 8; i++) {
	for (int j=0; j < 16; j++) {
	    cut_assert_equal_int (128 + 16 * i, mifare_classic_first_sector_block (128 + 16 * i), cut_message ("Wrong last block number for block %d", i));
	    cut_assert_equal_int (128 + 16 * i + 15, mifare_classic_last_sector_block (128 + 16 * i + j), cut_message ("Wrong last block number for block %d", i));
	}
    }
}

