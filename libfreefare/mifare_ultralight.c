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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>
#include "freefare_internal.h"

#define ASSERT_VALID_PAGE(page) do { if (page >= MIFARE_ULTRALIGHT_PAGE_COUNT) return errno = EINVAL, -1; } while (0)


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the target.
 */

/*
 * Get a list of the MIFARE card near to the provided NFC initiator.
 *
 * The list can be freed using the mifare_ultralight_free_tags() function.
 */
MifareUltralightTag *
mifare_ultralight_get_tags (nfc_device_t *device)
{
    MifareUltralightTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_configure(device,NDO_ACTIVATE_FIELD,false);

    // Let the reader only try once to find a tag
    nfc_configure(device,NDO_INFINITE_SELECT,false);

    // Configure the CRC and Parity settings
    nfc_configure(device,NDO_HANDLE_CRC,true);
    nfc_configure(device,NDO_HANDLE_PARITY,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_configure(device,NDO_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target_info_t target_info;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    while (nfc_initiator_select_tag(device,NM_ISO14443A_106,NULL,0,&target_info)) {

	// Ensure the target is a MIFARE UltraLight tag.
	if (!((target_info.nai.abtAtqa[0] == 0x00) &&
		    (target_info.nai.abtAtqa[1] == 0x44) &&
		    (target_info.nai.btSak == 0x00))) /* NXP MIFARE UltraLight */
	    continue;

	tag_count++;

	/* (Re)Allocate memory for the found MIFARE UltraLight array */
	MifareUltralightTag *p = realloc (tags, (tag_count) * sizeof (MifareUltralightTag) + sizeof (void *));
	if (p)
	    tags = p;
	else
	    return tags; // FAIL! Return what has been found so far.

	/* Allocate memory for the found MIFARE UltraLight tag */
	if (!(tags[tag_count-1] = malloc (sizeof (struct mifare_ultralight_tag)))) {
	    return tags; // FAIL! Return what has been found before.
	}
	(tags[tag_count-1])->device = device;
	(tags[tag_count-1])->info = target_info.nai;
	(tags[tag_count-1])->active = 0;
	for (int i = 0; i < MIFARE_ULTRALIGHT_PAGE_COUNT; i++) {
	    tags[tag_count-1]->cached_pages[i] = 0;
	}
	tags[tag_count] = NULL;

	nfc_initiator_deselect_tag (device);
    }

    return tags;
}

/*
 * Free the provided tag list.
 */
void
mifare_ultralight_free_tags (MifareUltralightTag *tags)
{
    if (tags) {
    	for (int i=0; tags[i]; i++) {
	    free (tags[i]);
	}
	free (tags);
    }
}

/*
 * Establish connection to the provided tag.
 */
int
mifare_ultralight_connect (MifareUltralightTag tag)
{
    ASSERT_INACTIVE (tag);

    nfc_target_info_t pnti;
    if (nfc_initiator_select_tag (tag->device, NM_ISO14443A_106, tag->info.abtUid, 7, &pnti)) {
	tag->active = 1;
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
mifare_ultralight_disconnect (MifareUltralightTag tag)
{
    ASSERT_ACTIVE (tag);

    if (nfc_initiator_deselect_tag (tag->device)) {
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
mifare_ultralight_read (MifareUltralightTag tag, MifareUltralightPageNumber page, MifareUltralightPage *data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_VALID_PAGE (page);

    if (!tag->cached_pages[page]) {
	uint8_t cmd[2];
	cmd[0] = 0x30;
	cmd[1] = page;

	size_t n;
	if (!(nfc_initiator_transceive_dep_bytes (tag->device, cmd, sizeof (cmd), tag->cache[page], &n))) {
	    errno = EIO;
	    return -1;
	}

	/* Handle wrapped pages */
	for (int i = MIFARE_ULTRALIGHT_PAGE_COUNT; i <= page + 3; i++) {
	    memcpy (tag->cache[i % MIFARE_ULTRALIGHT_PAGE_COUNT], tag->cache[i], sizeof (MifareUltralightPage));
	}

	/* Mark pages as cached */
	for (int i = page; i <= page + 3; i++) {
	    tag->cached_pages[i % MIFARE_ULTRALIGHT_PAGE_COUNT] = 1;
	}
    }

    memcpy (data, tag->cache[page], sizeof (*data));
    return 0;
}

/*
 * Read data to the provided MIFARE tag.
 */
int
mifare_ultralight_write (MifareUltralightTag tag, const MifareUltralightPageNumber page, const MifareUltralightPage data)
{
    ASSERT_ACTIVE (tag);
    ASSERT_VALID_PAGE (page);

    uint8_t cmd[6];
    cmd[0] = 0xA2;
    cmd[1] = page;
    memcpy (cmd + 2, data, sizeof (MifareUltralightPage));

    size_t n;
    if (!(nfc_initiator_transceive_dep_bytes (tag->device, cmd, sizeof (cmd), NULL, &n))) {
	errno = EIO;
	return -1;
    }

    /* Invalidate page in cache */
    tag->cached_pages[page] = 0;

    return 0;
}



/*
 * Miscellaneous functions
 */
char *
mifare_ultralight_get_uid (MifareUltralightTag tag)
{
    char *uid = malloc (2 * 7 + 1);
    MifareUltralightPage p0, p1;
    mifare_ultralight_read (tag, 0, &p0);
    mifare_ultralight_read (tag, 1, &p1);
    sprintf (uid, "%02x%02x%02x%02x%02x%02x%02x",
	    p0[0],
	    p0[1],
	    p0[2],
	    p1[0],
	    p1[1],
	    p1[2],
	    p1[3]);
    return uid;
}
