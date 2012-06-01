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

#define ASSERT_VALID_PAGE(tag, page, mode_write) \
    do { \
	if (IS_MIFARE_ULTRALIGHT_C(tag)) { \
	    if (mode_write) { \
		if (page >= MIFARE_ULTRALIGHT_C_PAGE_COUNT) return errno = EINVAL, -1; \
	    } else { \
		if (page >= MIFARE_ULTRALIGHT_C_PAGE_COUNT_READ) return errno = EINVAL, -1; \
	    } \
	} else { \
	    if (page >= MIFARE_ULTRALIGHT_PAGE_COUNT) return errno = EINVAL, -1; \
	} \
    } while (0)

#define ULTRALIGHT_TRANSCEIVE(tag, msg, res) \
    do { \
	errno = 0; \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	int _res; \
	if ((_res = nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, __##res##_size, 0)) < 0) { \
	    return errno = EIO, -1; \
	} \
	__##res##_n = _res; \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
    } while (0)

#define ULTRALIGHT_TRANSCEIVE_RAW(tag, msg, res) \
    do { \
	errno = 0; \
	if (nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, false) < 0) { \
	    errno = EIO; \
	    return -1; \
	} \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	int _res; \
	if ((_res = nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, __##res##_size, 0)) < 0) { \
	    nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, true); \
	    return errno = EIO, -1; \
	} \
	__##res##_n = _res; \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
	if (nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, true) < 0) { \
	    errno = EIO; \
	    return -1; \
	} \
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

    nfc_target pnti;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if (nfc_initiator_select_passive_target (tag->device, modulation, tag->info.abtUid, tag->info.szUidLen, &pnti) >= 0) {
	tag->active = 1;
	for (int i = 0; i < MIFARE_ULTRALIGHT_MAX_PAGE_COUNT; i++)
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

    if (nfc_initiator_deselect_target (tag->device) >= 0) {
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
    ASSERT_VALID_PAGE (tag, page, false);

    if (!MIFARE_ULTRALIGHT(tag)->cached_pages[page]) {
	BUFFER_INIT (cmd, 2);
	BUFFER_ALIAS (res, MIFARE_ULTRALIGHT(tag)->cache[page], sizeof(MifareUltralightPage));

	BUFFER_APPEND (cmd, 0x30);
	BUFFER_APPEND (cmd, page);

	ULTRALIGHT_TRANSCEIVE (tag, cmd, res);

	/* Handle wrapped pages */
	int iPageCount;
	if (IS_MIFARE_ULTRALIGHT_C(tag)) {
	    iPageCount = MIFARE_ULTRALIGHT_C_PAGE_COUNT_READ;
	} else {
	    iPageCount = MIFARE_ULTRALIGHT_PAGE_COUNT;
	}
	for (int i = iPageCount; i <= page + 3; i++) {
	    memcpy (MIFARE_ULTRALIGHT(tag)->cache[i % iPageCount], MIFARE_ULTRALIGHT(tag)->cache[i], sizeof (MifareUltralightPage));
	}

	/* Mark pages as cached */
	for (int i = page; i <= page + 3; i++) {
	    MIFARE_ULTRALIGHT(tag)->cached_pages[i % iPageCount] = 1;
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
    ASSERT_VALID_PAGE (tag, page, true);

    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xA2);
    BUFFER_APPEND (cmd, page);
    BUFFER_APPEND_BYTES (cmd, data, sizeof (MifareUltralightPage));

    ULTRALIGHT_TRANSCEIVE (tag, cmd, res);

    /* Invalidate page in cache */
    MIFARE_ULTRALIGHT(tag)->cached_pages[page] = 0;

    return 0;
}

/*
 * Authenticate to the provided MIFARE tag.
 */
int
mifare_ultralightc_authenticate (MifareTag tag, const MifareDESFireKey key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_ULTRALIGHT_C (tag);

    BUFFER_INIT (cmd1, 2);
    BUFFER_INIT (res, 9);
    BUFFER_APPEND (cmd1, 0x1A);
    BUFFER_APPEND (cmd1, 0x00);

    ULTRALIGHT_TRANSCEIVE_RAW(tag, cmd1, res);

    uint8_t PICC_E_RndB[8];
    memcpy (PICC_E_RndB, res+1, 8);

    uint8_t PICC_RndB[8];
    memcpy (PICC_RndB, PICC_E_RndB, 8);
    uint8_t ivect[8];
    memset (ivect, '\0', sizeof (ivect));
    mifare_cypher_single_block (key, PICC_RndB, ivect, MCD_RECEIVE, MCO_DECYPHER, 8);

    uint8_t PCD_RndA[8];
    DES_random_key ((DES_cblock*)&PCD_RndA);

    uint8_t PCD_r_RndB[8];
    memcpy (PCD_r_RndB, PICC_RndB, 8);
    rol (PCD_r_RndB, 8);

    uint8_t token[16];
    memcpy (token, PCD_RndA, 8);
    memcpy (token+8, PCD_r_RndB, 8);
    size_t offset = 0;

    while (offset < 16) {
	mifare_cypher_single_block (key, token + offset, ivect, MCD_SEND, MCO_ENCYPHER, 8);
	offset += 8;
    }

    BUFFER_INIT (cmd2, 17);

    BUFFER_APPEND (cmd2, 0xAF);
    BUFFER_APPEND_BYTES (cmd2, token, 16);

    ULTRALIGHT_TRANSCEIVE_RAW(tag, cmd2, res);

    uint8_t PICC_E_RndA_s[8];
    memcpy (PICC_E_RndA_s, res+1, 8);

    uint8_t PICC_RndA_s[8];
    memcpy (PICC_RndA_s, PICC_E_RndA_s, 8);
    mifare_cypher_single_block (key, PICC_RndA_s, ivect, MCD_RECEIVE, MCO_DECYPHER, 8);

    uint8_t PCD_RndA_s[8];
    memcpy (PCD_RndA_s, PCD_RndA, 8);
    rol (PCD_RndA_s, 8);

    if (0 != memcmp (PCD_RndA_s, PICC_RndA_s, 8)) {
	return -1;
    }
    // XXX Should we store the state "authenticated" in the tag struct??
    return 0;
}

/*
 * Callback for freefare_tag_new to test presence of a MIFARE UltralightC on the reader.
 */
bool
is_mifare_ultralightc_on_reader (nfc_device *device, nfc_iso14443a_info nai)
{
    int ret;
    uint8_t cmd_step1[2];
    uint8_t res_step1[9];
    cmd_step1[0] = 0x1A;
    cmd_step1[1] = 0x00;

    nfc_target pnti;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    nfc_initiator_select_passive_target (device, modulation, nai.abtUid, nai.szUidLen, &pnti);
    nfc_device_set_property_bool (device, NP_EASY_FRAMING, false);
    ret = nfc_initiator_transceive_bytes (device, cmd_step1, sizeof (cmd_step1), res_step1, sizeof(res_step1), 0);
    nfc_device_set_property_bool (device, NP_EASY_FRAMING, true);
    nfc_initiator_deselect_target (device);
    return ret >= 0;
}
