#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

void
test_mifare_classic_sector_boundaries(void)
{
    for (int i = 0; i < 32; i++) {
	for (int j = 0; j < 4; j++) {
	    cut_assert_equal_int(4 * i, mifare_classic_sector_first_block(mifare_classic_block_sector(4 * i)), cut_message("Wrong first block number for block %d", i));
	    cut_assert_equal_int(4 * i + 3, mifare_classic_sector_last_block(mifare_classic_block_sector(4 * i + j)), cut_message("Wrong last block number for block %d", i));
	}
    }

    for (int i = 0; i < 8; i++) {
	for (int j = 0; j < 16; j++) {
	    cut_assert_equal_int(128 + 16 * i, mifare_classic_sector_first_block(mifare_classic_block_sector(128 + 16 * i)), cut_message("Wrong last block number for block %d", i));
	    cut_assert_equal_int(128 + 16 * i + 15, mifare_classic_sector_last_block(mifare_classic_block_sector(128 + 16 * i + j)), cut_message("Wrong last block number for block %d", i));
	}
    }
}

