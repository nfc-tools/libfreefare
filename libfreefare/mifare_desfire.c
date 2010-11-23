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

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * Draft ISO/IEC FCD 14443-4
 * Identification cards
 *   - Contactless integrated circuit(s) cards
 *     - Proximity cards
 *       - Part 4: Transmission protocol
 * Final Committee Draft - 2000-03-10
 *
 * http://ridrix.wordpress.com/2009/09/19/mifare-desfire-communication-example/
 */

#include "config.h"

#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif

#if defined(HAVE_SYS_ENDIAN_H)
#  include <sys/endian.h>
#endif

#if defined(HAVE_ENDIAN_H)
#  include <endian.h>
#endif

#if defined(HAVE_COREFOUNDATION_COREFOUNDATION_H)
#  include <CoreFoundation/CoreFoundation.h>
#endif

#if defined(HAVE_BYTESWAP_H)
#  include <byteswap.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#ifdef WITH_DEBUG
#  include <libutil.h>
#endif

#include <openssl/rand.h>

#include <freefare.h>
#include "freefare_internal.h"

#pragma pack (push)
#pragma pack (1)
struct mifare_desfire_raw_file_settings {
    uint8_t file_type;
    uint8_t communication_settings;
    uint16_t access_rights;
    union {
	struct {
	    uint8_t file_size[3];
	} standard_file;
	struct {
	    int32_t lower_limit;
	    int32_t upper_limit;
	    int32_t limited_credit_value;
	    uint8_t limited_credit_enabled;
	} value_file;
	struct {
	    uint8_t record_size[3];
	    uint8_t max_number_of_records[3];
	    uint8_t current_number_of_records[3];
	} linear_record_file;
    } settings;
};
#pragma pack (pop)

#define MAX_APPLICATION_COUNT 28
#define MAX_FILE_COUNT 16

static struct mifare_desfire_file_settings cached_file_settings[MAX_FILE_COUNT];
static bool cached_file_settings_current[MAX_FILE_COUNT];

static int	 create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
static int	 create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
static ssize_t	 write_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
static ssize_t	 read_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs);

#define MAX_FRAME_SIZE 60

#define NOT_YET_AUTHENTICATED 255

#define ASSERT_AUTHENTICATED(tag) \
    do { \
	if (MIFARE_DESFIRE (tag)->authenticated_key_no == NOT_YET_AUTHENTICATED) { \
	    return errno = EINVAL, -1;\
	} \
    } while (0)

/*
 * XXX: cs < 0 is a CommunicationSettings detection error. Other values are
 * user erros. We may need to distinguish them.
 */
#define ASSERT_CS(cs) \
    do { \
	if (cs < 0) { \
	    return errno = EINVAL, -1; \
	} else if (cs == 0x02) { \
	    return errno = EINVAL, -1; \
	} else if (cs > 0x03) { \
	    return errno = EINVAL, -1; \
	} \
    } while (0)

#define ASSERT_NOT_NULL(argument) \
    do { \
	if (!argument) { \
	    return errno = EINVAL, -1; \
	} \
    } while (0)


/*
 * Convenience macros.
 */

static uint8_t __msg[MAX_FRAME_SIZE] = { 0x90, 0x00, 0x00, 0x00, 0x00, /* ..., */ 0x00 };
/*                                       CLA   INS   P1    P2    Lc    PAYLOAD    LE*/
static uint8_t __res[MAX_FRAME_SIZE];

#define FRAME_PAYLOAD_SIZE (MAX_FRAME_SIZE - 6)

/*
 * Transmit the message msg to the NFC tag and receive the response res.  The
 * response buffer's size is set according to the quantity of data received.
 *
 * The Mifare DESFire function return value which is returned at the end of the
 * response is copied at the beginning to match the PICC documentation.
 */
#define DESFIRE_TRANSCEIVE(tag, msg, res) \
    DESFIRE_TRANSCEIVE2 (tag, msg, __##msg##_n, res)
#define DESFIRE_TRANSCEIVE2(tag, msg, msg_len, res) \
    do { \
	size_t __len = 5; \
	errno = 0; \
	__msg[1] = msg[0]; \
	if (msg_len > 1) { \
	    __len += msg_len; \
	    __msg[4] = msg_len - 1; \
	    memcpy (__msg + 5, msg + 1, msg_len - 1); \
	} \
	__msg[__len-1] = 0x00; \
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK; \
	DEBUG_XFER (__msg, __len, "===> "); \
	if (!(nfc_initiator_transceive_bytes (tag->device, __msg, __len, __res, &__##res##_n))) { \
	    return errno = EIO, -1; \
	} \
	DEBUG_XFER (__res, __##res##_n, "<=== "); \
	memcpy (res, __res, __##res##_n - 2); \
	res[__##res##_n-2] = __res[__##res##_n-1]; \
	__##res##_n-=1; \
	if ((1 == __##res##_n) && (OPERATION_OK != res[__##res##_n-1]) && (ADDITIONAL_FRAME != res[__##res##_n-1])) { \
	    return MIFARE_DESFIRE (tag)->last_picc_error = res[__##res##_n-1], -1; \
	} \
    } while (0)


/*
 * Miscellaneous low-level memory manipulation functions.
 */

static void	*memdup (void *p, size_t n);
static int32_t	 le24toh (uint8_t data[3]);

int
madame_soleil_get_read_communication_settings (MifareTag tag, uint8_t file_no)
{
    struct mifare_desfire_file_settings settings;
    if (mifare_desfire_get_file_settings (tag, file_no, &settings))
	return -1;

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no == MDAR_READ (settings.access_rights)) ||
	(MIFARE_DESFIRE (tag)->authenticated_key_no == MDAR_READ_WRITE (settings.access_rights)))
	return settings.communication_settings;
    else
	return 0;
}

int
madame_soleil_get_write_communication_settings (MifareTag tag, uint8_t file_no)
{
    struct mifare_desfire_file_settings settings;
    if (mifare_desfire_get_file_settings (tag, file_no, &settings))
	return -1;

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no == MDAR_WRITE (settings.access_rights)) ||
	(MIFARE_DESFIRE (tag)->authenticated_key_no == MDAR_READ_WRITE (settings.access_rights)))
	return settings.communication_settings;
    else
	return 0;
}

static int32_t
le24toh (uint8_t data[3])
{
    return (data[2] << 16) | (data[1] << 8) | data[0];
}

static void *
memdup (void *p, size_t n)
{
    void *res;
    if ((res = malloc (n))) {
	memcpy (res, p, n);
    }
    return res;
}


/*
 * Memory management functions.
 */

/*
 * Allocates and initialize a MIFARE DESFire tag.
 */
MifareTag
mifare_desfire_tag_new (void)
{
    MifareTag tag;
    if ((tag= malloc (sizeof (struct mifare_desfire_tag)))) {
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->last_pcd_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->session_key = NULL;
	MIFARE_DESFIRE (tag)->crypto_buffer = NULL;
	MIFARE_DESFIRE (tag)->crypto_buffer_size = 0;
    }
    return tag;
}

/*
 * Free the provided tag.
 */
void
mifare_desfire_tag_free (MifareTag tag)
{
    free (MIFARE_DESFIRE (tag)->session_key);
    free (MIFARE_DESFIRE (tag)->crypto_buffer);
    free (tag);
}


/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleannups after using
 * the target.
 */

/*
 * Establish connection to the provided tag.
 */
int
mifare_desfire_connect (MifareTag tag)
{
    ASSERT_INACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    nfc_target_t pnti;
    nfc_modulation_t modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if (nfc_initiator_select_passive_target (tag->device, modulation, tag->info.abtUid, tag->info.szUidLen, &pnti)) {
	tag->active = 1;
	free (MIFARE_DESFIRE (tag)->session_key);
	MIFARE_DESFIRE (tag)->session_key = NULL;
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->last_pcd_error = OPERATION_OK;
	MIFARE_DESFIRE (tag)->authenticated_key_no = NOT_YET_AUTHENTICATED;
	MIFARE_DESFIRE (tag)->block_number = 0;
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
mifare_desfire_disconnect (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE(tag)->session_key = NULL;

    if (nfc_initiator_deselect_target (tag->device)) {
	tag->active = 0;
    }
    return 0;
}



int
mifare_desfire_authenticate (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    bzero (MIFARE_DESFIRE (tag)->ivect, MAX_CRYPTO_BLOCK_SIZE);

    MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;

    MIFARE_DESFIRE (tag)->authenticated_key_no = NOT_YET_AUTHENTICATED;
    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;

    BUFFER_INIT (cmd1, 2);
    BUFFER_INIT (res, 9);

    BUFFER_APPEND (cmd1, 0x0A);
    BUFFER_APPEND (cmd1, key_no);

    DESFIRE_TRANSCEIVE (tag, cmd1, res);


    uint8_t PICC_E_RndB[8];
    memcpy (PICC_E_RndB, res, 8);

    uint8_t PICC_RndB[8];
    memcpy (PICC_RndB, PICC_E_RndB, 8);
    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect,  PICC_RndB, 8, MD_RECEIVE, 0);

    uint8_t PCD_RndA[8];
    RAND_bytes (PCD_RndA, 8);

    uint8_t PCD_r_RndB[8];
    memcpy (PCD_r_RndB, PICC_RndB, 8);
    rol (PCD_r_RndB, 8);

    uint8_t token[16];
    memcpy (token, PCD_RndA, 8);
    memcpy (token+8, PCD_r_RndB, 8);

    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, token, 16, MD_SEND, 0);

    BUFFER_INIT (cmd2, 17);

    BUFFER_APPEND (cmd2, 0xAF);
    BUFFER_APPEND_BYTES (cmd2, token, 16);

    DESFIRE_TRANSCEIVE (tag, cmd2, res);

    uint8_t PICC_E_RndA_s[8];
    memcpy (PICC_E_RndA_s, res, 8);

    uint8_t PICC_RndA_s[8];
    memcpy (PICC_RndA_s, PICC_E_RndA_s, 8);
    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, PICC_RndA_s, 8, MD_RECEIVE, 0);

    uint8_t PCD_RndA_s[8];
    memcpy (PCD_RndA_s, PCD_RndA, 8);
    rol (PCD_RndA_s, 8);


    if (0 != memcmp (PCD_RndA_s, PICC_RndA_s, 8)) {
	return -1;
    }

    MIFARE_DESFIRE (tag)->authenticated_key_no = key_no;
    MIFARE_DESFIRE (tag)->session_key = mifare_desfire_session_key_new (PCD_RndA, PICC_RndB, key);
    bzero (MIFARE_DESFIRE (tag)->ivect, MAX_CRYPTO_BLOCK_SIZE);

    return 0;
}

int
mifare_desfire_change_key_settings (MifareTag tag, uint8_t settings)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 9);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x54);

    uint8_t data[8];

    data[0] = settings;
    iso14443a_crc (data, 1, data + 1);
    bzero (data+3, 5);

    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, data, 8, MD_SEND, 0);

    BUFFER_APPEND_BYTES (cmd, data, 8);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_get_key_settings (MifareTag tag, uint8_t *settings, uint8_t *max_keys)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 3);

    BUFFER_APPEND (cmd, 0x45);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    if (settings)
	*settings = res[0];
    if (max_keys)
	*max_keys = res[1];

    return 0;
}

int
mifare_desfire_change_key (MifareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 1+1+24);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xC4);
    BUFFER_APPEND (cmd, key_no);

    uint8_t data[24];

    if (MIFARE_DESFIRE (tag)->authenticated_key_no != key_no) {
	if (old_key) {
	    memcpy (data, old_key->data, 16);
	} else {
	    bzero (data, 16);
	}
	for (int n=0; n<16; n++) {
	    data[n] ^= new_key->data[n];
	}
	// Append XORed data CRC
	iso14443a_crc (data, 16, data+16);
	// Append new key CRC
	iso14443a_crc (new_key->data, 16, data+18);
	// Padding
	for (int n=20; n<24; n++) {
	    data[n] = 0x00;
	}
    } else {
	memcpy (data, new_key->data, 16);
	// Append new key CRC
	iso14443a_crc (data, 16, data+16);

	// Padding
	for (int n=18; n<24; n++) {
	    data[n] = 0x00;
	}
    }

    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, data, 24, MD_SEND, 0);

    BUFFER_APPEND_BYTES (cmd, data, 24);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

/*
 * Retrieve version information for a given key.
 */
int
mifare_desfire_get_key_version (MifareTag tag, uint8_t key_no, uint8_t *version)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (version);

    BUFFER_INIT (cmd, 2);
    BUFFER_APPEND (cmd, 0x64);
    BUFFER_APPEND (cmd, key_no);

    BUFFER_INIT (res, 2);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    *version = res[0];

    return 0;
}



int
mifare_desfire_create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 6);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xCA);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));
    BUFFER_APPEND (cmd, settings);
    BUFFER_APPEND (cmd, key_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_delete_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 4);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xDA);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_get_application_ids (MifareTag tag, MifareDESFireAID *aids[], size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, MAX_FRAME_SIZE);

    BUFFER_APPEND (cmd, 0x6A);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    *count = (BUFFER_SIZE (res)-1)/3;
    *aids = malloc ((*count + 1) * sizeof (MifareDESFireAID));
    for (size_t i = 0; (3*i + 1) < BUFFER_SIZE (res); i++) {
	(*aids)[i] = memdup (res + 3*i, 3);
    }

    if (res[__res_n-1] == 0xAF) {
	cmd[0] = 0xAF;
	DESFIRE_TRANSCEIVE (tag, cmd, res);
	*count += (BUFFER_SIZE (res)-1) / 3;

	MifareDESFireAID *p;
	if ((p = realloc (*aids, (*count + 1) * sizeof (MifareDESFireAID)))) {
	    *aids = p;

	    for (size_t i = 0; (3*i) < BUFFER_SIZE (res); i++) {
		(*aids)[19+i] = memdup (res + 3*i, 3);
	    }
	}
    }

    (*aids)[*count] = NULL;

    return 0;
}

void
mifare_desfire_free_application_ids (MifareDESFireAID aids[])
{
    for (int i = 0; aids[i]; i++)
	free (aids[i]);
    free (aids);
}

/*
 * Select the application specified by aid for further operation.  If aid is
 * NULL, the master application is selected (equivalent to aid = 0x00000).
 */
int
mifare_desfire_select_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    struct mifare_desfire_aid null_aid = { .data = { 0x00, 0x00, 0x00 } };

    if (!aid) {
	aid = &null_aid;
    }

    BUFFER_INIT (cmd, 4);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x5A);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    for (int n = 0; n < MAX_FILE_COUNT; n++)
	cached_file_settings_current[n] = false;

    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;

    return 0;
}

int
mifare_desfire_format_picc (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xFC);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

/*
 * Retrieve version information form the PICC.
 */
int
mifare_desfire_get_version (MifareTag tag, struct mifare_desfire_version_info *version_info)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (version_info);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 15); /* 8, 8, then 15 byte results */

    BUFFER_APPEND (cmd, 0x60);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->hardware), res, 7);

    cmd[0] = 0xAF;
    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->software), res, 7);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->uid), res, 14);

    return 0;
}



/* Application level commands */

int
mifare_desfire_get_file_ids (MifareTag tag, uint8_t *files[], size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 16);

    BUFFER_APPEND (cmd, 0x6F);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    *count = BUFFER_SIZE (res) - 1;

    if (!(*files = malloc (*count))) {
	errno = ENOMEM;
	return -1;
    }
    memcpy (*files, res, *count);

    return 0;
}

int
mifare_desfire_get_file_settings (MifareTag tag, uint8_t file_no, struct mifare_desfire_file_settings *settings)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    if (cached_file_settings_current[file_no]) {
	*settings = cached_file_settings[file_no];
	return 0;
    }

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 18);

    BUFFER_APPEND (cmd, 0xF5);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    struct mifare_desfire_raw_file_settings raw_settings;
    memcpy (&raw_settings, res, BUFFER_SIZE (res));

    settings->file_type = raw_settings.file_type;
    settings->communication_settings = raw_settings.communication_settings;
    settings->access_rights = le16toh (raw_settings.access_rights);

    switch (settings->file_type) {
    case MDFT_STANDARD_DATA_FILE:
    case MDFT_BACKUP_DATA_FILE:
	settings->settings.standard_file.file_size = le24toh (raw_settings.settings.standard_file.file_size);
	break;
    case MDFT_VALUE_FILE_WITH_BACKUP:
	settings->settings.value_file.lower_limit = le32toh (raw_settings.settings.value_file.lower_limit);
	settings->settings.value_file.upper_limit = le32toh (raw_settings.settings.value_file.upper_limit);
	settings->settings.value_file.limited_credit_value = le32toh (raw_settings.settings.value_file.limited_credit_value);
	settings->settings.value_file.limited_credit_enabled = raw_settings.settings.value_file.limited_credit_enabled;
	break;
    case MDFT_LINEAR_RECORD_FILE_WITH_BACKUP:
    case MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP:
	settings->settings.linear_record_file.record_size = le24toh (raw_settings.settings.linear_record_file.record_size);
	settings->settings.linear_record_file.max_number_of_records = le24toh (raw_settings.settings.linear_record_file.max_number_of_records);
	settings->settings.linear_record_file.current_number_of_records = le24toh (raw_settings.settings.linear_record_file.current_number_of_records);
	break;
    }

    cached_file_settings[file_no] = *settings;
    cached_file_settings_current[file_no] = true;

    return 0;
}

int
mifare_desfire_change_file_settings (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    struct mifare_desfire_file_settings settings;
    int res = mifare_desfire_get_file_settings (tag, file_no, &settings);
    if (res < 0)
	return res;

    cached_file_settings_current[file_no] = false;

    if (MDAR_CHANGE_AR(settings.access_rights) == MDAR_FREE) {
	BUFFER_INIT (cmd, 5);
	BUFFER_INIT (res, 1);

	BUFFER_APPEND (cmd, 0x5F);
	BUFFER_APPEND (cmd, file_no);
	BUFFER_APPEND (cmd, communication_settings);
	BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));

	DESFIRE_TRANSCEIVE (tag, cmd, res);
    } else {
	BUFFER_INIT (cmd, 10);
	BUFFER_INIT (res, 1);

	uint8_t data[8];

	BUFFER_APPEND (cmd, 0x5F);
	BUFFER_APPEND (cmd, file_no);

	data[0] = communication_settings;
	uint16_t le_ar = htole16 (access_rights);
	memcpy (data + 1, &le_ar, sizeof (le_ar));
	iso14443a_crc (data, 3, data+3);
	bzero (data + 5, 3);
	mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, data, 8, MD_SEND, 0);

	BUFFER_APPEND_BYTES (cmd, data, 8);

	DESFIRE_TRANSCEIVE (tag, cmd, res);
    }

    return 0;
}

static int
create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 8);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, file_size, 3, sizeof (uint32_t));

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_create_std_data_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)
{
    return create_file1 (tag, 0xCD, file_no, communication_settings, access_rights, file_size);
}

int
mifare_desfire_create_backup_data_file  (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)
{
    return create_file1 (tag, 0xCB, file_no, communication_settings, access_rights, file_size);
}

int
mifare_desfire_create_value_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit_enable)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 18);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xCC);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, lower_limit, 4, sizeof (int32_t));
    BUFFER_APPEND_LE (cmd, upper_limit, 4, sizeof (int32_t));
    BUFFER_APPEND_LE (cmd, value, 4, sizeof (int32_t));
    BUFFER_APPEND (cmd, limited_credit_enable);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

static int
create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 11);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, record_size, 3, sizeof (uint32_t));
    BUFFER_APPEND_LE (cmd, max_number_of_records, 3, sizeof (uint32_t));

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_create_linear_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)
{
    return create_file2 (tag, 0xC1, file_no, communication_settings, access_rights, record_size, max_number_of_records);
}

int
mifare_desfire_create_cyclic_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)
{
    return create_file2 (tag, 0xC0, file_no, communication_settings, access_rights, record_size, max_number_of_records);
}

int
mifare_desfire_delete_file (MifareTag tag, uint8_t file_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xDF);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}


/*
 * Data manipulation commands.
 */

static ssize_t
read_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    ssize_t bytes_read = 0;

    void *p = data;

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 8);
    BUFFER_INIT (res, MAX_FRAME_SIZE);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, offset, 3, sizeof (off_t));
    BUFFER_APPEND_LE (cmd, length, 3, sizeof (size_t));

    if (cs) {
	if (!(p = assert_crypto_buffer_size (tag, MAX_FRAME_SIZE - 1)))
	    return -1;
    }

    do {
	ssize_t frame_bytes;

	DESFIRE_TRANSCEIVE (tag, cmd, res);

	frame_bytes = BUFFER_SIZE (res) - 1;
	memcpy ((uint8_t *)p + bytes_read, res, frame_bytes);
	bytes_read += frame_bytes;

	if (res[__res_n-1] == 0xAF) {
	    if (p != data) {
		// If we are handling memory, request more for next frame.
		if (!(p = assert_crypto_buffer_size (tag, bytes_read + MAX_FRAME_SIZE - 1)))
		    return -1;

	    }
	    BUFFER_CLEAR (cmd);
	    BUFFER_APPEND (cmd, 0xAF);
	}

    } while (res[__res_n-1] != 0x00);

    if (cs) {
	if (mifare_cryto_postprocess_data (tag, p, &bytes_read, cs))
	    memcpy (data, p, bytes_read);
    }

    return bytes_read;
}

ssize_t
mifare_desfire_read_data (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data)
{
    return mifare_desfire_read_data_ex (tag, file_no, offset, length, data, madame_soleil_get_read_communication_settings (tag, file_no));
}

ssize_t
mifare_desfire_read_data_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    return read_data (tag, 0xBD, file_no, offset, length, data, cs);
}

static ssize_t
write_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    size_t bytes_left;
    size_t bytes_send = 0;

    void *p = data;

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 8 + length);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, offset, 3, sizeof (off_t));
    BUFFER_APPEND_LE (cmd, length, 3, sizeof (size_t));
    BUFFER_APPEND_BYTES (cmd, data, length);

    p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 8, cs);

    BUFFER_INIT(d, FRAME_PAYLOAD_SIZE);
    bytes_left = FRAME_PAYLOAD_SIZE;

    while (bytes_send < __cmd_n) {
	size_t frame_bytes = MIN(bytes_left, __cmd_n - bytes_send);
	BUFFER_APPEND_BYTES (d, (uint8_t *) p + bytes_send, frame_bytes);

	DESFIRE_TRANSCEIVE (tag, d, res);

	bytes_send += frame_bytes;

	if (0x00 == res[__res_n-1])
	    break;

	// PICC returned 0xAF and expects more data
	BUFFER_CLEAR (d);
	BUFFER_APPEND (d, 0xAF);
	bytes_left = FRAME_PAYLOAD_SIZE - 1;
    }

    if (0x00 == res[__res_n-1]) {
	// Remove header length
	bytes_send -= 8;
    } else {
	// 0xAF (additionnal Frame) failure can happen here (wrong crypto method).
	MIFARE_DESFIRE (tag)->last_picc_error = res[__res_n-1];
	bytes_send = -1;
    }

    cached_file_settings_current[file_no] = false;

    return bytes_send;
}

ssize_t
mifare_desfire_write_data (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data)
{
    return mifare_desfire_write_data_ex (tag, file_no, offset, length, data, madame_soleil_get_write_communication_settings (tag, file_no));
}

ssize_t
mifare_desfire_write_data_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    return write_data (tag, 0x3D, file_no, offset, length, data, cs);
}

int
mifare_desfire_get_value (MifareTag tag, uint8_t file_no, int32_t *value)
{
    return mifare_desfire_get_value_ex (tag, file_no, value, madame_soleil_get_read_communication_settings (tag, file_no));
}
int
mifare_desfire_get_value_ex (MifareTag tag, uint8_t file_no, int32_t *value, int cs)
{
    if (!value)
	return errno = EINVAL, -1;

    void *p;

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 9);

    BUFFER_APPEND (cmd, 0x6C);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    p = (uint8_t *)res;

    if (cs) {
	ssize_t rdl = BUFFER_SIZE (res) - 1;
	p = mifare_cryto_postprocess_data (tag, p, &rdl, cs);
	if (rdl != 4) {
	    printf ("invalid data length");
	    return -1;
	}
    }

    *value = le32toh (*(int32_t *)(p));

    return 0;
}

int
mifare_desfire_credit (MifareTag tag, uint8_t file_no, int32_t amount)
{
    return mifare_desfire_credit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
}

int
mifare_desfire_credit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 10);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x0C);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_debit (MifareTag tag, uint8_t file_no, int32_t amount)
{
    return mifare_desfire_debit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
}
int
mifare_desfire_debit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 10);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xDC);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_limited_credit (MifareTag tag, uint8_t file_no, int32_t amount)
{
    return mifare_desfire_limited_credit_ex (tag, file_no, amount, madame_soleil_get_write_communication_settings (tag, file_no));
}
int
mifare_desfire_limited_credit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 10);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0x1C);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

ssize_t
mifare_desfire_write_record (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data)
{
    return mifare_desfire_write_record_ex (tag, file_no, offset, length, data, madame_soleil_get_write_communication_settings (tag, file_no));
}
ssize_t
mifare_desfire_write_record_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    return write_data (tag, 0x3B, file_no, offset, length, data, cs);
}

ssize_t
mifare_desfire_read_records (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data)
{
    return mifare_desfire_read_records_ex (tag, file_no, offset, length, data, madame_soleil_get_read_communication_settings (tag, file_no));
}

ssize_t
mifare_desfire_read_records_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    return read_data (tag, 0xBB, file_no, offset, length, data, cs);
}

int
mifare_desfire_clear_record_file (MifareTag tag, uint8_t file_no)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 2);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xEB);
    BUFFER_APPEND (cmd, file_no);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_commit_transaction (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xC7);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

int
mifare_desfire_abort_transaction (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 1);

    BUFFER_APPEND (cmd, 0xA7);

    DESFIRE_TRANSCEIVE (tag, cmd, res);

    return 0;
}

