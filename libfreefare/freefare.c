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
#include <pcsclite.h>
#include <winscard.h>
#include <reader.h>
#include "freefare_internal.h"

#define MAX_CANDIDATES 16

#define NXP_MANUFACTURER_CODE 0x04

struct supported_tag supported_tags[] = {
    { CLASSIC_1K,   "Mifare Classic 1k",            0x08, 0, 0, { 0x00 }, NULL },
    { CLASSIC_1K,   "Infineon Mifare Classic 1k",   0x88, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k",            0x18, 0, 0, { 0x00 }, NULL },
    { CLASSIC_4K,   "Mifare Classic 4k (Emulated)", 0x38, 0, 0, { 0x00 }, NULL },
    { DESFIRE,      "Mifare DESFire",               0x20, 5, 4, { 0x75, 0x77, 0x81, 0x02 /*, 0xXX */ }, NULL},
    { ULTRALIGHT_C, "Mifare UltraLightC",           0x00, 0, 0, { 0x00 }, is_mifare_ultralightc_on_reader },
    { ULTRALIGHT,   "Mifare UltraLight",            0x00, 0, 0, { 0x00 }, NULL },
};

/*
 * Automagically allocate a MifareTag given a device and target info.
 */
MifareTag
freefare_tag_new (nfc_device *device, nfc_iso14443a_info nai)
{
    bool found = false;
    struct supported_tag *tag_info;
    MifareTag tag;

    /* Ensure the target is supported */
    for (size_t i = 0; i < sizeof (supported_tags) / sizeof (struct supported_tag); i++) {
	if (((nai.szUidLen == 4) || (nai.abtUid[0] == NXP_MANUFACTURER_CODE)) &&
	    (nai.btSak == supported_tags[i].SAK) &&
	    (!supported_tags[i].ATS_min_length || ((nai.szAtsLen >= supported_tags[i].ATS_min_length) &&
						   (0 == memcmp (nai.abtAts, supported_tags[i].ATS, supported_tags[i].ATS_compare_length)))) &&
	    ((supported_tags[i].check_tag_on_reader == NULL) ||
	     supported_tags[i].check_tag_on_reader(device, nai))) {

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
    case ULTRALIGHT_C:
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

MifareTag
freefare_tag_new_pcsc (SCARDCONTEXT context, SCARDHANDLE handle)
{
    bool found = false;
    struct supported_tag *tag_info;
    MifareTag tag;

    LONG l;
    LPBYTE pbAttr = NULL;
    DWORD value = SCARD_AUTOALLOCATE;
    LPDWORD pcbAttrLen = &value;

    l = SCardGetAttrib ( handle, SCARD_ATTR_ATR_STRING , (unsigned char*)&pbAttr, pcbAttrLen);
  
    if (l != SCARD_S_SUCCESS) {
	/* error handling ? */
	fprintf(stderr, "Handle was: 0x%lx SCardGetAttrib %lx\n", handle, l);
	return 0; 
    }

    const char* desfire_tag = "\x3b\x81\x80\x01\x80\x80";
    
    if ((*pcbAttrLen == 6) && (! memcmp(pbAttr, desfire_tag, 6))){
	tag = mifare_desfire_tag_new ();
 	fprintf(stderr, "valid TAG\n");
    } else {
	fprintf(stderr, "invalid TAG\n");
    }

    if(SCARD_S_SUCCESS != SCardFreeMemory(context, pbAttr))
    {
	fprintf(stderr, "SCardFreeMemory failed.\n");
    }

    if (!tag)
	return NULL;

    /*
     * Initialize common fields
     * (Target specific fields are initialized in mifare_*_tag_new())
     */
    tag->device = NULL;
    tag->active = 0;
    tag->info; 
    tag->tag_info = &supported_tags[4];

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
freefare_get_tags (nfc_device *device)
{
    MifareTag *tags = NULL;
    int tag_count = 0;

    nfc_initiator_init(device);

    // Drop the field for a while
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,false);

    // Configure the CRC and Parity settings
    nfc_device_set_property_bool(device,NP_HANDLE_CRC,true);
    nfc_device_set_property_bool(device,NP_HANDLE_PARITY,true);
    nfc_device_set_property_bool(device,NP_AUTO_ISO14443_4,true);

    // Enable field so more power consuming cards can power themselves up
    nfc_device_set_property_bool(device,NP_ACTIVATE_FIELD,true);

    // Poll for a ISO14443A (MIFARE) tag
    nfc_target candidates[MAX_CANDIDATES];
    int candidates_count;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if ((candidates_count = nfc_initiator_list_passive_targets(device, modulation, candidates, MAX_CANDIDATES)) < 0)
	return NULL;

    tags = malloc(sizeof (void *));
    if(!tags) return NULL;
    tags[0] = NULL;

    for (int c = 0; c < candidates_count; c++) {
	MifareTag t;
	if ((t = freefare_tag_new(device, candidates[c].nti.nai))) {
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
 * Get a list of the MIFARE targets near to the provided NFC initiator.
 * (Usally its just one tag, because pcsc can not detect more)
 * phContext must be established with SCardEstablishContext before 
 * calling this function.
 * mszReader is the Name of the SmartCard Reader to use
 * The list has to be freed using the freefare_free_tags() function.
 */
MifareTag *
freefare_get_tags_pcsc (struct pcsc_context *context, LPCSTR szReader)
{
    MifareTag 	*tags = NULL;
    DWORD	dwActiveProtocol;
    LONG	rv;
    SCARDHANDLE hCard;

    rv = SCardConnect(context->context, szReader, SCARD_SHARE_SHARED, 
			SCARD_PROTOCOL_T0, &hCard, &dwActiveProtocol);
    if(SCARD_S_SUCCESS != rv)
    {
	fprintf(stderr, "freefare_get_tags_pcsc: SCardConnect failed !!\n");
	return tags;
    }

    tags = malloc(sizeof (void *));    
    if(!tags)
    {
	fprintf(stderr, "freefare_get_tags_pcsc: malloc failed !!\n");
	return NULL;
    }
    tags[0] = NULL;

    MifareTag t;
    if(NULL != (t = freefare_tag_new_pcsc(context->context, hCard)))
    {
	MifareTag *p = realloc (tags, 2 * sizeof (MifareTag));
	if (p)
	    tags = p;
	else
	{
    	    fprintf(stderr, "freefare_get_tags_pcsc: realloc failed !!\n");
	    return tags; // FAIL! Return what has been found so far.
	}

	/* set info data for pcsc , can we do this earlier? */
	/* get and set card uid */
	uint8_t buf[] = { 0xFF, 0xCA, 0x00, 0x00, 0x00 };
	uint8_t ret[12];
	LONG err;
	SCARD_IO_REQUEST ioreq;
	DWORD retlen = sizeof(ret);
	err = SCardTransmit(hCard, SCARD_PCI_T0, buf, sizeof(buf), &ioreq, ret, &retlen);
	// TODO: proper error handling
	if (err != SCARD_S_SUCCESS)
	{
	    fprintf(stderr, "getting uid failed\n");
	    return tags;
	}
	memcpy(t->info.abtUid, ret, retlen - 2);
	t->info.szUidLen = retlen - 2;


	t->device = NULL;	// we dont wanna use nfclib, so device is not needed !
	t->hCard = hCard;
	t->lastPCSCerror = rv;
	tags[0] = t;
	tags[1] = NULL;
    }
    else
    {
	fprintf(stderr, "freefare_get_tags_pcsc: freefare_tag_new_pcsc call failed !!\n"); 
    }

    FILL_SZREADER(szReader);

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
        case ULTRALIGHT_C:
            mifare_ultralight_tag_free (tag);
            break;
        }
    }
}

const char *
freefare_strerror (MifareTag tag)
{
    const char *p = "Unknown error";
    if(tag->device != NULL) // we use libnfc
    {
	if (nfc_device_get_last_error (tag->device) < 0) {
	    p = nfc_strerror (tag->device);
	} else {
	    if (tag->tag_info->type == DESFIRE) {
	    	if (MIFARE_DESFIRE (tag)->last_pcd_error) {
		    p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_pcd_error);
	    	} else if (MIFARE_DESFIRE (tag)->last_picc_error) {
	            p = mifare_desfire_error_lookup (MIFARE_DESFIRE (tag)->last_picc_error);
	    	}
	    }
	}
    }
    else // we use the pcsc protocol
    {
	p = (const char*) pcsc_stringify_error(tag->lastPCSCerror);
    }
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

/*
 * create context for pcsc readers
 */

void
pcsc_init(struct pcsc_context** context)
{
	LONG err;
	struct pcsc_context *con =  malloc(sizeof(struct pcsc_context));
	err = SCardEstablishContext(SCARD_SCOPE_SYSTEM, NULL, NULL, &con->context);
	if (err < 0)
	{
		*context = NULL;
		return;
	}
	*context = con;
}

/*
 * destroy context for pcsc readers
 */
void
pcsc_exit(struct pcsc_context* context)
{
	if (context->readers)
		SCardFreeMemory(context->context, context->readers);
	SCardReleaseContext(context->context);
}

/*
 * list pcsc devices
 */

LONG
pcsc_list_devices(struct pcsc_context* context, LPSTR *string)
{
	LONG err;
	LPSTR str = NULL;
	DWORD size;
	static char empty[] = "\0";
	size = SCARD_AUTOALLOCATE;
	err = SCardListReaders(context->context, NULL, (LPSTR)&str, &size);
	if (err != SCARD_S_SUCCESS)
	{
		context->readers = NULL;
		*string = empty;
	}
	else
	{
		*string = str;
		context->readers = str;
	}
	return err;
}

/*
 * Low-level API
 */

void *
memdup (const void *p, const size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}
