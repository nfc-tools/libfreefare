/*-
 * Copyright (C) 2015, Romain Tartiere.
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
 * This implementation was written based on information provided by the
 * following documents:
 *
 * FeliCa Lite User's Manual
 * Version 1.2
 * No. M624-E01-20
 */

#include "config.h"

#include <assert.h>
#include <errno.h>
#include <string.h>

#include <sys/types.h>

#ifdef WITH_DEBUG
#  include <libutil.h>
#endif

#include <freefare.h>
#include "freefare_internal.h"

#define MAX_BLOCK_COUNT 8

inline static
ssize_t felica_transceive (FreefareTag tag, uint8_t *data_in, uint8_t *data_out, size_t data_out_length)
{
    DEBUG_XFER (data_in, data_in[0], "===> ");
    ssize_t res = nfc_initiator_transceive_bytes (tag->device, data_in, data_in[0], data_out, data_out_length, 0);
    DEBUG_XFER (data_out, res, "<=== ");
    return res;
}

bool
felica_taste (nfc_device *device, nfc_target target)
{
    (void) device;
    return target.nm.nmt == NMT_FELICA;
}

FreefareTag
felica_tag_new (void)
{
    return malloc (sizeof (struct felica_tag));
}

void
felica_tag_free (FreefareTag tag)
{
    free (tag);
}



ssize_t
felica_read_ex (FreefareTag tag, uint16_t service, uint8_t block_count, uint8_t blocks[], uint8_t *data, size_t length)
{
    assert (block_count <= MAX_BLOCK_COUNT);
    assert (length == 16 * block_count);

    DEBUG_FUNCTION();

    uint8_t cmd[1 + 1 + 8 + 1 + 2 + 1 + 2 * MAX_BLOCK_COUNT] = {
	0x00, /* Length */
	0x06,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01,
	0x00, 0x00, /* Service */
	0x00,
	/* Block ... */
    };

    uint8_t res[100];

    cmd[0] = 14 + 2 * block_count;
    memcpy (cmd + 2, tag->info.nti.nfi.abtId, 8);
    cmd[11] = service;
    cmd[12] = service >> 8;
    cmd[13] = block_count;

    for (int i = 0; i < block_count; i++) {
	cmd[14 + 2*i] = 0x80;
	cmd[14 + 2*i + 1] = blocks[i];
    }

    int cnt = felica_transceive (tag, cmd, res, sizeof (res));
    if (cnt != 1 + 1 + 8 + 1 + 1 + 1 + 16 * block_count) {
	return -1;
    }
    size_t len = MIN(res[12] * 16, length);
    memcpy (data, res + 13, len);

    return len;
}

ssize_t
felica_read (FreefareTag tag, uint16_t service, uint8_t block, uint8_t *data, size_t length)
{
    uint8_t blocks[] = {
	block
    };

    return felica_read_ex (tag, service, 1, blocks, data, length);
}

ssize_t
felica_write_ex (FreefareTag tag, uint16_t service, uint8_t block_count, uint8_t blocks[], uint8_t *data, size_t length)
{
    DEBUG_FUNCTION();

    assert (block_count <= MAX_BLOCK_COUNT);
    assert (length == 16 * block_count);

    uint8_t cmd[1 + 1 + 8 + 1 + 2 + 1 + 2 + 16 * MAX_BLOCK_COUNT] = {
	0x00, /* Length */
	0x08,
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x01,
	0x00, 0x00, /* Service */
	0x00,
	/* Block ... */
	/* n * 16 */
    };

    uint8_t res[12];

    cmd[0] = 1 + 1 + 8 + 1 + 2 * 1 + 1 + 2 * 1 + 16 * block_count;
    memcpy (cmd + 2, tag->info.nti.nfi.abtId, 8);
    cmd[11] = service;
    cmd[12] = service >> 8;
    cmd[13] = block_count;

    for (int i = 0; i < block_count; i++) {
	cmd[14 + 2*i] = 0x80;
	cmd[14 + 2*i + 1] = blocks[i];
    }

    memcpy (cmd + 14 + 2 * block_count, data, length);

    ssize_t cnt = felica_transceive (tag, cmd, res, sizeof (res));

    if (cnt != sizeof (res))
	return -1;

    return res[10] == 0 ? 0 : -1;
}

ssize_t
felica_write (FreefareTag tag, uint16_t service, uint8_t block, uint8_t *data, size_t length)
{
    uint8_t blocks[] = {
	block
    };

    return felica_write_ex (tag, service, 1, blocks, data, length);
}
