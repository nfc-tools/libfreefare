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

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * Contactless Single-trip Ticket IC
 * MF0 IC U1
 * Functional Specification
 * Revision 3.0
 * March 2003
 */

#include "config.h"

#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_DEBUG
#  include <libutil.h>
#endif

#include <freefare.h>
#include "freefare_internal.h"

#define ASSERT_VALID_PAGE(page) do { if (page >= MIFARE_ULTRALIGHT_PAGE_COUNT) return errno = EINVAL, -1; } while (0)

#define ULTRALIGHT_TRANSCEIVE(tag, msg, res) \
    do { \
	errno = 0; \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	if (!(nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, &__##res##_n))) { \
	    return errno = EIO, -1; \
	} \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
    } while (0)


/*
 * Memory management functions.
 */

/*
 * Allocates and initialize a MIFARE UltraLight tag.
 */
MifareTag
mifare_ultralight_tag_new (void)
{
    return malloc (sizeof (struct mifare_ultralight_tag));
}

/*
 * Free the provided tag.
 */
void
mifare_ultralight_tag_free (MifareTag tag)
{
    free (tag);
}


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleanups after using
 * the target.
 */


/*
 * Establish connection to the provided tag.
 */
int
mifare_ultralight_connect (MifareTag tag)
{
    ASSERT_INACTIVE (tag);
    ASSERT_MIFARE_ULTRALIGHT (tag);

    nfc_target_t pnti;
    nfc_modulation_t modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if (nfc_initiator_select_passive_target (tag->device, modulation, tag->info.abtUid, tag->info.szUidLen, &pnti)) {
	tag->active = 1;
	for (int i = 0; i < MIFARE_ULTRALIGHT_PAGE_COUNT; i++)
	    MIFARE_ULTRALIGHT(tag)->cached_pages[i] = 0;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}

/*
 * Terminate connection with the provided tag.
 */
int
mifare_ultralight_disconnect (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_ULTRALIGHT (tag);

    if (nfc_initiator_deselect_target (tag->device)) {
	tag->active = 0;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}


/*
 * Card manipulation functions
 *
 * The following functions perform direct communication with the connected
 * MIFARE UltraLight tag.
 */

/*
 * Read data from the provided MIFARE tag.
 */
int
mifare_ultralight_read (MifareTag tag, MifareUltralightPageNumber page, MifareUltralightPage *data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_ULTRALIGHT (tag);
    ASSERT_VALID_PAGE (page);

    if (!MIFARE_ULTRALIGHT(tag)->cached_pages[page]) {
	BUFFER_INIT (cmd, 2);
	BUFFER_ALIAS (res, MIFARE_ULTRALIGHT(tag)->cache[page]);

	BUFFER_APPEND (cmd, 0x30);
	BUFFER_APPEND (cmd, page);

	ULTRALIGHT_TRANSCEIVE (tag, cmd, res);

	/* Handle wrapped pages */
	for (int i = MIFARE_ULTRALIGHT_PAGE_COUNT; i <= page + 3; i++) {
	    memcpy (MIFARE_ULTRALIGHT(tag)->cache[i % MIFARE_ULTRALIGHT_PAGE_COUNT], MIFARE_ULTRALIGHT(tag)->cache[i], sizeof (MifareUltralightPage));
	}

	/* Mark pages as cached */
	for (int i = page; i <= page + 3; i++) {
	    MIFARE_ULTRALIGHT(tag)->cached_pages[i % MIFARE_ULTRALIGHT_PAGE_COUNT] = 1;
	}
    }

    memcpy (data, MIFARE_ULTRALIGHT(tag)->cache[page], sizeof (*data));
    return 0;
}

/*
 * Read data to the provided MIFARE tag.
 */
int
mifare_ultralight_write (MifareTag tag, const MifareUltralightPageNumber page, const MifareUltralightPage data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_ULTRALIGHT (tag);
    ASSERT_VALID_PAGE (page);

    uint8_t cmd[6];
    cmd[0] = 0xA2;
    cmd[1] = page;
    memcpy (cmd + 2, data, sizeof (MifareUltralightPage));

    size_t n;
    if (!(nfc_initiator_transceive_bytes (tag->device, cmd, sizeof (cmd), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    /* Invalidate page in cache */
    MIFARE_ULTRALIGHT(tag)->cached_pages[page] = 0;

    return 0;
}
