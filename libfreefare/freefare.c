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

#include <stdlib.h>
#include <string.h>

#include <freefare.h>

#include "freefare_internal.h"

#define MAX_CANDIDATES 16

#define NXP_MANUFACTURER_CODE 0x04

/* Number of bytes of ATS to compare */
#define ATS_LENGTH 4

struct supported_tag supported_tags[] = {
    { CLASSIC_1K, "Mifare Classic 1k",            0x08, 0, { 0x00 } },
    { CLASSIC_4K, "Mifare Classic 4k",            0x18, 0, { 0x00 } },
    { CLASSIC_4K, "Mifare Classic 4k (Emulated)", 0x38, 0, { 0x00 } },
    { DESFIRE,    "Mifare DESFire",               0x20, 5, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }},
    { ULTRALIGHT, "Mifare UltraLight",            0x00, 0, { 0x00 } },
};

/*
 * Automagically allocate a MifareTag given a device and target info.
 */
static MifareTag
freefare_tag_new (nfc_device_t *device, nfc_iso14443a_info_t nai)
{
    bool found = false;
    struct supported_tag *tag_info;
    MifareTag tag;

    /* Ensure the target is supported */
    for (size_t i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (((nai.szUidLen == 4) || (nai.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (nai.btSak == supported_tags[i].SAK) &&
	    (nai.szAtsLen == supported_tags[i].ATS_length) &&
	    (0 == memcmp (nai.abtAts, supported_tags[i].ATS, ATS_LENGTH))) {

	    tag_info = &(supported_tags[i]);
	    found = true;
	    break;
	}
    }

    if (!found)
	return NULL;

    /* Allocate memory for the found MIFARE target */
    switch (tag_info->type) {
    case CLASSIC_1K:
    case CLASSIC_4K:
	tag = mifare_classic_tag_new ();
	break;
    case DESFIRE:
	tag = mifare_desfire_tag_new ();
	break;
    case ULTRALIGHT:
	tag = mifare_ultralight_tag_new ();
	break;
    }

    if (!tag)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    tag->device = device;
    tag->info = nai;
    tag->active = 0;
    tag->tag_info = tag_info;

    return tag;
}


/*
 * MIFARE card common functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the targets.
 */

/*
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 *
 * The list has to be freed using the freefare_free_tags() function.
 */
MifareTag *
freefare_get_tags (nfc_device_t *device)
{
    MifareTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_configure(device,NDO_ACTIVATE_FIELD,false);

    // Configure the CRC and Parity settings
    nfc_configure(device,NDO_HANDLE_CRC,true);
    nfc_configure(device,NDO_HANDLE_PARITY,true);
    nfc_configure(device,NDO_AUTO_ISO14443_4,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_configure(device,NDO_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target_info_t candidates[MAX_CANDIDATES];
    size_t candidates_count;
    if (!nfc_initiator_list_passive_targets(device, NM_ISO14443A_106, candidates, MAX_CANDIDATES, &candidates_count))
	return NULL;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    for (size_t c = 0; c < candidates_count; c++) {
	MifareTag t;
	if ((t = freefare_tag_new(device, candidates[c].nai))) {
	    /* (Re)Allocate memory for the found MIFARE targets array */
	    MifareTag *p = realloc (tags, (tag_count + 2) * sizeof (MifareTag));
	    if (p)
		tags = p;
	    else
		return tags; // FAIL! Return what has been found so far.
	    tags[tag_count++] = t;
	    tags[tag_count] = NULL;
	}
    }

    return tags;
}

/*
 * Returns the type of the provided tag.
 */
enum mifare_tag_type
freefare_get_tag_type (MifareTag tag)
{
    return tag->tag_info->type;
}

/*
 * Returns the friendly name of the provided tag.
 */
const char *
freefare_get_tag_friendly_name (MifareTag tag)
{
    return tag->tag_info->friendly_name;
}

/*
 * Returns the UID of the provided tag.
 */
char *
freefare_get_tag_uid (MifareTag tag)
{
    char *res = malloc (2 * tag->info.szUidLen + 1);
    for (size_t i =0; i < tag->info.szUidLen; i++)
	snprintf (res + 2*i, 3, "%02x", tag->info.abtUid[i]);
    return res;
}

/*
 * Free the provided tag.
 */
void
freefare_free_tag (MifareTag tag)
{
    if (tag) {
	switch (tag->tag_info->type) {
	case CLASSIC_1K:
	case CLASSIC_4K:
	    mifare_classic_tag_free (tag);
	    break;
	case DESFIRE:
	    mifare_desfire_tag_free (tag);
	    break;
	case ULTRALIGHT:
	    mifare_ultralight_tag_free (tag);
	    break;
	}
    }
}

const char *
freefare_strerror (MifareTag tag)
{
    const char *p = "Unkown error";
    if (tag->device->iLastError > 0)
	p = nfc_strerror (tag->device);
    else if (tag->tag_info->type == DESFIRE)
	p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);

    return p;
}

int
freefare_strerror_r (MifareTag tag, char *buffer, size_t len)
{
    return (snprintf (buffer, len, "%s", freefare_strerror (tag)) < 0) ? -1 : 0;
}

void
freefare_perror (MifareTag tag, const char *string)
{
    fprintf (stderr, "%s: %s\n", string, freefare_strerror (tag));
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags (MifareTag *tags)
{
    if (tags) {
	for (int i=0; tags[i]; i++) {
	    freefare_free_tag(tags[i]);
	}
	free (tags);
    }
}
