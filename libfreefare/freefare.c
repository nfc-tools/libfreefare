/*
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

#include <freefare.h>

#include "freefare_internal.h"

struct supported_tag {
    uint8_t ATQA[2], SAK;
    enum mifare_tag_type type;
};

struct supported_tag supported_tags[] = {
    { { 0x00, 0x44 }, 0x00, ULTRALIGHT },
    { { 0x00, 0x04 }, 0x08, CLASSIC_1K },
    { { 0x00, 0x02 }, 0x18, CLASSIC_4K },
    { { 0x00, 0x02 }, 0x38, CLASSIC_4K },  /* Emulated */
};


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

	bool found = false;
	enum mifare_tag_type type;

	for (int i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	    if ((target_info.nai.abtAtqa[0] == supported_tags[i].ATQA[0]) &&
		(target_info.nai.abtAtqa[1] == supported_tags[i].ATQA[1]) &&
		(target_info.nai.btSak == supported_tags[i].SAK)) {

		type = supported_tags[i].type;
		found = true;
		break;
	    }
	}

	if (!found)
	    continue;

	tag_count++;

	/* (Re)Allocate memory for the found MIFARE targets array */
	MifareTag *p = realloc (tags, (tag_count + 1) * sizeof (MifareTag));
	if (p)
	    tags = p;
	else
	    return tags; // FAIL! Return what has been found so far.

	/* Allocate memory for the found MIFARE target */
	switch (type) {
	    case CLASSIC_1K:
	    case CLASSIC_4K:
		tags[tag_count-1] = mifare_classic_tag_new ();
		break;
	    case ULTRALIGHT:
		tags[tag_count-1] = mifare_ultralight_tag_new ();
		break;
	}

	if (!tags[tag_count-1])
	    return tags; // FAIL! Return what has been found before.

	/*
	 * Initialize common fields
	 * (Target specific fields are initialized in mifare_*_tag_new())
	 */
	(tags[tag_count-1])->device = device;
	(tags[tag_count-1])->info = target_info.nai;
	(tags[tag_count-1])->active = 0;
	(tags[tag_count-1])->type = type;
	tags[tag_count] = NULL;

	nfc_initiator_deselect_tag (device);
    }

    return tags;
}

/*
 * Returns the type of the provided tag.
 */
enum mifare_tag_type
freefare_get_tag_type (MifareTag tag)
{
    return tag->type;
}

/*
 * Free the provided tag list.
 */
void
freefare_free_tags (MifareTag *tags)
{
    if (tags) {
	for (int i=0; tags[i]; i++) {
	    switch (tags[i]->type) {
		case CLASSIC_1K:
		case CLASSIC_4K:
		    mifare_classic_tag_free (tags[i]);
		    break;
		case ULTRALIGHT:
		    mifare_ultralight_tag_free (tags[i]);
		    break;
	    }
	}
	free (tags);
    }
}
