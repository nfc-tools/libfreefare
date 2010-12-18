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
#define MAX_FILE_COUNT 32

#define CMAC_LENGTH 8

static struct mifare_desfire_file_settings cached_file_settings[MAX_FILE_COUNT];
static bool cached_file_settings_current[MAX_FILE_COUNT];

static int	 authenticate (MifareTag tag, uint8_t cmd, uint8_t key_no, MifareDESFireKey key);
static int	 create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
static int	 create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
static ssize_t	 write_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
static ssize_t	 read_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs);

#define NOT_YET_AUTHENTICATED 255

#define ASSERT_AUTHENTICATED(tag) \
    do { \
	if (MIFARE_DESFIRE (tag)->authenticated_key_no == NOT_YET_AUTHENTICATED) { \
	    return errno = EINVAL, -1;\
	} \
    } while (0)

/*
 * XXX: cs < 0 is a CommunicationSettings detection error. Other values are
 * user errors. We may need to distinguish them.
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

uint8_t cmac_cmd_buf[4096];
uint8_t cmac_res_buf[4096];
size_t cmac_cmd_len = 0;
size_t cmac_res_len = 0;

#define FRAME_PAYLOAD_SIZE (MAX_FRAME_SIZE - 5)

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
	/* reply length */ \
	__msg[__len-1] = 0x00; \
	MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK; \
	DEBUG_XFER (__msg, __len, "===> "); \
	if (!(nfc_initiator_transceive_bytes (tag->device, __msg, __len, __res, &__##res##_n))) { \
	    return errno = EIO, -1; \
	} \
	DEBUG_XFER (__res, __##res##_n, "<=== "); \
	res[__##res##_n-2] = __res[__##res##_n-1]; \
	__##res##_n--; \
	if ((1 == __##res##_n) && (ADDITIONAL_FRAME != res[__##res##_n-1]) && (OPERATION_OK != res[__##res##_n-1])) { \
	    return MIFARE_DESFIRE (tag)->last_picc_error = res[0], -1; \
	} \
	memcpy (res, __res, __##res##_n - 1); \
    } while (0)


/*
 * Miscellaneous low-level memory manipulation functions.
 */

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
	MIFARE_DESFIRE (tag)->selected_application = 0;
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



static int
authenticate (MifareTag tag, uint8_t cmd, uint8_t key_no, MifareDESFireKey key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    memset (MIFARE_DESFIRE (tag)->ivect, 0, MAX_CRYPTO_BLOCK_SIZE);

    MIFARE_DESFIRE (tag)->last_picc_error = OPERATION_OK;

    MIFARE_DESFIRE (tag)->authenticated_key_no = NOT_YET_AUTHENTICATED;
    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;

    BUFFER_INIT (cmd1, 2);
    BUFFER_INIT (res, 17);

    BUFFER_APPEND (cmd1, cmd);
    BUFFER_APPEND (cmd1, key_no);

    DESFIRE_TRANSCEIVE (tag, cmd1, res);

    size_t key_length = __res_n - 1;

    uint8_t PICC_E_RndB[16];
    memcpy (PICC_E_RndB, res, key_length);

    uint8_t PICC_RndB[16];
    memcpy (PICC_RndB, PICC_E_RndB, key_length);
    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, PICC_RndB, key_length, MD_RECEIVE, 0);

    uint8_t PCD_RndA[16];
    RAND_bytes (PCD_RndA, 16);

    uint8_t PCD_r_RndB[16];
    memcpy (PCD_r_RndB, PICC_RndB, key_length);
    rol (PCD_r_RndB, key_length);

    uint8_t token[32];
    memcpy (token, PCD_RndA, key_length);
    memcpy (token+key_length, PCD_r_RndB, key_length);

    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, token, 2 * key_length, MD_SEND, (0x0A == cmd) ? 0 : 1);

    BUFFER_INIT (cmd2, 33);

    BUFFER_APPEND (cmd2, 0xAF);
    BUFFER_APPEND_BYTES (cmd2, token, 2*key_length);

    DESFIRE_TRANSCEIVE (tag, cmd2, res);

    uint8_t PICC_E_RndA_s[16];
    memcpy (PICC_E_RndA_s, res, key_length);

    uint8_t PICC_RndA_s[16];
    memcpy (PICC_RndA_s, PICC_E_RndA_s, key_length);
    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, PICC_RndA_s, key_length, MD_RECEIVE, 0);

    uint8_t PCD_RndA_s[key_length];
    memcpy (PCD_RndA_s, PCD_RndA, key_length);
    rol (PCD_RndA_s, key_length);


    if (0 != memcmp (PCD_RndA_s, PICC_RndA_s, key_length)) {
#ifdef WITH_DEBUG
	hexdump (PCD_RndA_s, key_length, "PCD  ", 0);
	hexdump (PICC_RndA_s, key_length, "PICC ", 0);
#endif
	return -1;
    }

    MIFARE_DESFIRE (tag)->authenticated_key_no = key_no;
    MIFARE_DESFIRE (tag)->session_key = mifare_desfire_session_key_new (PCD_RndA, PICC_RndB, key);
    memset (MIFARE_DESFIRE (tag)->ivect, 0, MAX_CRYPTO_BLOCK_SIZE);

    switch (MIFARE_DESFIRE (tag)->session_key->type) {
    case T_DES:
    case T_3DES:
	break;
    case T_3K3DES:
    case T_AES:
	cmac_generate_subkeys (MIFARE_DESFIRE (tag)->session_key);
	break;
    }

    return 0;
}

int
mifare_desfire_authenticate (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    return authenticate (tag, 0x0A, key_no, key);
}

int
mifare_desfire_authenticate_iso (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    return authenticate (tag, 0x1A, key_no, key);
}

int
mifare_desfire_authenticate_aes (MifareTag tag, uint8_t key_no, MifareDESFireKey key)
{
    return authenticate (tag, 0xAA, key_no, key);
}

int
mifare_desfire_change_key_settings (MifareTag tag, uint8_t settings)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 9 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x54);
    BUFFER_APPEND (cmd, settings);

    char *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 1, MDCM_ENCIPHERED | ENC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t n = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &n, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY | MAC_COMMAND | MAC_VERIFY);

    return 0;
}

int
mifare_desfire_get_key_settings (MifareTag tag, uint8_t *settings, uint8_t *max_keys)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 3 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x45);

    char *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 1, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t n = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &n, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    if (settings)
	*settings = p[0];
    if (max_keys)
	*max_keys = p[1] & 0x0F;

    return 0;
}

int
mifare_desfire_change_key (MifareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 42);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    key_no &= 0x0F;

    /*
     * Because new crypto methods can be setup only at application creation,
     * changing the card master key to one of them require a key_no tweak.
     */
    if (0x000000 == MIFARE_DESFIRE (tag)->selected_application) {
	switch (new_key->type) {
	case T_DES:
	case T_3DES:
	    break;
	case T_3K3DES:
	    key_no |= 0x40;
	    break;
	case T_AES:
	    key_no |= 0x80;
	    break;
	}
    }

    BUFFER_APPEND (cmd, 0xC4);
    BUFFER_APPEND (cmd, key_no);

    int new_key_length;
    switch (new_key->type) {
	case T_DES:
	case T_3DES:
	case T_AES:
	    new_key_length = 16;
	    break;
	case T_3K3DES:
	    new_key_length = 24;
	    break;
    }

    memcpy (cmd + __cmd_n, new_key->data, new_key_length);

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
	if (old_key) {
	    for (int n = 0; n < new_key_length; n++) {
		cmd[__cmd_n + n] ^= old_key->data[n];
	    }
	}
    }

    __cmd_n += new_key_length;

    if (new_key->type == T_AES)
	cmd[__cmd_n++] = new_key->aes_version;

    if ((MIFARE_DESFIRE (tag)->authenticated_key_no & 0x0f) != (key_no & 0x0f)) {
	switch (MIFARE_DESFIRE (tag)->session_key->type) {
	case T_DES:
	case T_3DES:
	    iso14443a_crc_append (cmd + 2, __cmd_n - 2);
	    __cmd_n += 2;
	    iso14443a_crc (new_key->data, new_key_length, cmd + __cmd_n);
	    __cmd_n += 2;
	    break;
	case T_3K3DES:
	case T_AES:
	    desfire_crc32_append (cmd, __cmd_n);
	    __cmd_n += 4;

	    desfire_crc32 (new_key->data, new_key_length, cmd + __cmd_n);
	    __cmd_n += 4;
	    break;
	}
    } else {
	switch (MIFARE_DESFIRE (tag)->session_key->type) {
	case T_DES:
	case T_3DES:
	    iso14443a_crc_append (cmd + 2 , __cmd_n - 2);
	    __cmd_n += 2;
	    break;
	case T_3K3DES:
	case T_AES:
	    desfire_crc32_append (cmd, __cmd_n);
	    __cmd_n += 4;
	    break;
	}
    }

    uint8_t * p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | ENC_COMMAND | NO_CRC);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    /*
     * If we changed the current authenticated key, we are not authenticated
     * anymore.
     */
    if (key_no == MIFARE_DESFIRE (tag)->authenticated_key_no) {
	free (MIFARE_DESFIRE (tag)->session_key);
	MIFARE_DESFIRE (tag)->session_key = NULL;
    }

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

    BUFFER_INIT (res, 2 + CMAC_LENGTH);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY | MAC_VERIFY);

    *version = p[0];

    return 0;
}



int
create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings1, uint8_t settings2, uint16_t iso_file_id, char *iso_file_name)
{
    (void) iso_file_id;
    (void) iso_file_name;

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 22);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xCA);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));
    BUFFER_APPEND (cmd, settings1);
    BUFFER_APPEND (cmd, settings2);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY | MAC_VERIFY);

    return 0;
}

int
mifare_desfire_create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no)
{
    return create_application (tag, aid, settings, key_no, 0, NULL);
}

int
mifare_desfire_delete_application (MifareTag tag, MifareDESFireAID aid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 4 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xDA);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    /*
     * If we have deleted the current application, we are not authenticated
     * anymore.
     */
    if (MIFARE_DESFIRE (tag)->selected_application == (uint32_t)(aid->data[0] | aid->data[1] << 8 | aid->data[2] << 16)) {
	free (MIFARE_DESFIRE (tag)->session_key);
	MIFARE_DESFIRE (tag)->session_key = NULL;
	MIFARE_DESFIRE (tag)->selected_application = 0x000000;
    }

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

    uint8_t buffer[3*MAX_APPLICATION_COUNT + CMAC_LENGTH + 1];
    *count = 0;

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    // FIXME This code needs refactoring!
    memcpy (buffer, res, __res_n);

    if (res[__res_n-1] == 0xAF) {
	off_t offset = __res_n - 1;
	p[0] = 0xAF;
	DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	memcpy ((uint8_t *)buffer + offset, res, __res_n);
	__res_n += offset;
    }

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, buffer, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY | MAC_VERIFY);

    *count = (sn - 1)/3;

    *aids = malloc (sn - 1);
    if (!(*aids = malloc ((*count + 1) * sizeof (MifareDESFireAID))))
	return -1;

    for (size_t i = 0; i < *count; i++) {
	if (!((*aids)[i] = memdup (p + 3 * i, 3))) {
	    while (i--) {
		free ((*aids)[i]);
	    }
	    free (aids);
	    return -1;
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

    BUFFER_INIT (cmd, 4 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x5A);
    BUFFER_APPEND_LE (cmd, aid->data, sizeof (aid->data), sizeof (aid->data));

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND);

    for (int n = 0; n < MAX_FILE_COUNT; n++)
	cached_file_settings_current[n] = false;

    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;

    MIFARE_DESFIRE (tag)->selected_application = aid->data[0] | aid->data[1] << 8 | aid->data[2] << 16;

    return 0;
}

int
mifare_desfire_format_picc (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_AUTHENTICATED (tag);

    BUFFER_INIT (cmd, 1 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xFC);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    free (MIFARE_DESFIRE (tag)->session_key);
    MIFARE_DESFIRE (tag)->session_key = NULL;
    MIFARE_DESFIRE (tag)->selected_application = 0x000000;

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
    BUFFER_INIT (res, 14 + CMAC_LENGTH); /* 8, 8, then 15 byte results */

    char buffer[28 + CMAC_LENGTH + 1];

    BUFFER_APPEND (cmd, 0x60);
    uint8_t *b = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->hardware), res, 7);
    memcpy (buffer, res, 7);

    cmd[0] = 0xAF;
    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->software), res, 7);
    memcpy (buffer + 7, res, 7);

    DESFIRE_TRANSCEIVE (tag, cmd, res);
    memcpy (&(version_info->uid), res, 14);
    memcpy (buffer + 14, res, __res_n);

    ssize_t sn = 28 + CMAC_LENGTH + 1;
    b = mifare_cryto_postprocess_data (tag, buffer, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    return 0;
}

int
mifare_desfire_free_mem (MifareTag tag, uint32_t *size)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (size);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 4 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x6E);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    *size = p[0] | (p[1] << 8) | (p[2] << 16);

    return 0;
}

int
mifare_desfire_set_configuration (MifareTag tag, bool disable_format, bool enable_random_uid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 10);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x5C);
    BUFFER_APPEND (cmd, 0x00);
    BUFFER_APPEND (cmd, (enable_random_uid ? 0x02 : 0x00) | (disable_format ? 0x01 : 0x00));

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | ENC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    return 0;
}

int
mifare_desfire_get_card_uid (MifareTag tag, char **uid)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    ASSERT_NOT_NULL (uid);

    BUFFER_INIT (cmd, 1);
    BUFFER_INIT (res, 17 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x51);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 1, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_ENCIPHERED);

    if (!(*uid = malloc (2*7+1))) {
	return -1;
    }

    sprintf (*uid, "%02x%02x%02x%02x%02x%02x%02x",
             p[0], p[1], p[2], p[3],
	     p[4], p[5], p[6]);

    return 0;
}



/* Application level commands */

int
mifare_desfire_get_file_ids (MifareTag tag, uint8_t *files[], size_t *count)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1 + CMAC_LENGTH);
    BUFFER_INIT (res, 16 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x6F);


    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    *count = sn - 1;

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

    BUFFER_INIT (cmd, 2 + CMAC_LENGTH);
    BUFFER_INIT (res, 18 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xF5);
    BUFFER_APPEND (cmd, file_no);
    
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    struct mifare_desfire_raw_file_settings raw_settings;
    memcpy (&raw_settings, p, sn - 1);

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
	BUFFER_INIT (cmd, 5 + CMAC_LENGTH);
	BUFFER_INIT (res, 1 + CMAC_LENGTH);

	BUFFER_APPEND (cmd, 0x5F);
	BUFFER_APPEND (cmd, file_no);
	BUFFER_APPEND (cmd, communication_settings);
	BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));

	uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);
	DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	ssize_t sn = __res_n;
	p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);
    } else {
	BUFFER_INIT (cmd, 10);
	BUFFER_INIT (res, 1 + CMAC_LENGTH);

	BUFFER_APPEND (cmd, 0x5F);
	BUFFER_APPEND (cmd, file_no);
	BUFFER_APPEND (cmd, communication_settings);
	BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));

	uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, MDCM_ENCIPHERED | ENC_COMMAND);

	DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	ssize_t sn = __res_n;
	p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);
    }

    return 0;
}

static int
create_file1 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 8 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, file_size, 3, sizeof (uint32_t));

    char *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

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

    BUFFER_INIT (cmd, 18 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xCC);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, lower_limit, 4, sizeof (int32_t));
    BUFFER_APPEND_LE (cmd, upper_limit, 4, sizeof (int32_t));
    BUFFER_APPEND_LE (cmd, value, 4, sizeof (int32_t));
    BUFFER_APPEND (cmd, limited_credit_enable);

    char *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, communication_settings | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, communication_settings | CMAC_COMMAND | CMAC_VERIFY);

    cached_file_settings_current[file_no] = false;

    return 0;
}

static int
create_file2 (MifareTag tag, uint8_t command, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 11 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND (cmd, communication_settings);
    BUFFER_APPEND_LE (cmd, access_rights, 2, sizeof (uint16_t));
    BUFFER_APPEND_LE (cmd, record_size, 3, sizeof (uint32_t));
    BUFFER_APPEND_LE (cmd, max_number_of_records, 3, sizeof (uint32_t));

    char *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, communication_settings | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, communication_settings | CMAC_COMMAND | CMAC_VERIFY);

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

    BUFFER_INIT (cmd, 2 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xDF);
    BUFFER_APPEND (cmd, file_no);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    return 0;
}


/*
 * Data manipulation commands.
 */

static ssize_t
read_data (MifareTag tag, uint8_t command, uint8_t file_no, off_t offset, size_t length, void *data, int cs)
{
    size_t bytes_received = 0;

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 8);
    BUFFER_INIT (res, MAX_FRAME_SIZE);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, offset, 3, sizeof (off_t));
    BUFFER_APPEND_LE (cmd, length, 3, sizeof (size_t));

    uint8_t ocs = cs;
    if ((MIFARE_DESFIRE (tag)->session_key) && (cs | MDCM_MACED)) {
	switch (MIFARE_DESFIRE (tag)->session_key->type) {
	case T_DES:
	case T_3DES:
	    break;
	case T_3K3DES:
	case T_AES:
	    cs = MDCM_PLAIN;
	    break;
	}
    }
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 8, cs | CMAC_COMMAND);
    cs = ocs;

    /*
     * FIXME: This is bogus: the user has to provide a data buffer with enougth
     * room to store CRC + padding or MAC.  If the user wants to read 1 byte,
     * there is no reason to provide a 16 bytes buffer.
     */
    do {
	DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

	size_t frame_bytes = BUFFER_SIZE (res) - 1;
	memcpy ((uint8_t *)data + bytes_received, res, frame_bytes);
	bytes_received += frame_bytes;

	p[0] = 0xAF;
	__cmd_n = 1;
    } while (0xAF == res[__res_n-1]);

    ((uint8_t *)data)[bytes_received++] = 0x00;

    ssize_t sr = bytes_received;
    p = mifare_cryto_postprocess_data (tag, data, &sr, cs | CMAC_COMMAND | CMAC_VERIFY | MAC_VERIFY);

    return sr - 1;
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

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 8 + length + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, command);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, offset, 3, sizeof (off_t));
    BUFFER_APPEND_LE (cmd, length, 3, sizeof (size_t));
    BUFFER_APPEND_BYTES (cmd, data, length);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 8, cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);

    BUFFER_INIT(d, FRAME_PAYLOAD_SIZE);
    bytes_left = FRAME_PAYLOAD_SIZE - 8;

    while (bytes_send < __cmd_n) {
	size_t frame_bytes = MIN(bytes_left, __cmd_n - bytes_send);
	BUFFER_APPEND_BYTES (d, p + bytes_send, frame_bytes);

	DESFIRE_TRANSCEIVE (tag, d, res);

	bytes_send += frame_bytes;

	if (0x00 == res[__res_n-1])
	    break;

	// PICC returned 0xAF and expects more data
	BUFFER_CLEAR (d);
	BUFFER_APPEND (d, 0xAF);
	bytes_left = FRAME_PAYLOAD_SIZE - 1;
    }

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_MACED | CMAC_COMMAND | CMAC_VERIFY);

    if (0x00 == p[__res_n-1]) {
	// Remove header length
	bytes_send -= 8;
    } else {
	// 0xAF (additionnal Frame) failure can happen here (wrong crypto method).
	MIFARE_DESFIRE (tag)->last_picc_error = p[__res_n-1];
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

    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);
    ASSERT_CS (cs);

    BUFFER_INIT (cmd, 2 + CMAC_LENGTH);
    BUFFER_INIT (res, 9 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x6C);
    BUFFER_APPEND (cmd, file_no);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, cs | CMAC_COMMAND | CMAC_VERIFY | MAC_VERIFY);

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

    BUFFER_INIT (cmd, 10 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x0C);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

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

    BUFFER_INIT (cmd, 10 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xDC);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

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

    BUFFER_INIT (cmd, 10 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0x1C);
    BUFFER_APPEND (cmd, file_no);
    BUFFER_APPEND_LE (cmd, amount, 4, sizeof (int32_t));
    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 2, cs | MAC_COMMAND | CMAC_COMMAND | ENC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    p = mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

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

    BUFFER_INIT (cmd, 2 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xEB);
    BUFFER_APPEND (cmd, file_no);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    cached_file_settings_current[file_no] = false;

    return 0;
}

int
mifare_desfire_commit_transaction (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xC7);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    return 0;
}

int
mifare_desfire_abort_transaction (MifareTag tag)
{
    ASSERT_ACTIVE (tag);
    ASSERT_MIFARE_DESFIRE (tag);

    BUFFER_INIT (cmd, 1 + CMAC_LENGTH);
    BUFFER_INIT (res, 1 + CMAC_LENGTH);

    BUFFER_APPEND (cmd, 0xA7);

    uint8_t *p = mifare_cryto_preprocess_data (tag, cmd, &__cmd_n, 0, MDCM_PLAIN | CMAC_COMMAND);

    DESFIRE_TRANSCEIVE2 (tag, p, __cmd_n, res);

    ssize_t sn = __res_n;
    mifare_cryto_postprocess_data (tag, res, &sn, MDCM_PLAIN | CMAC_COMMAND | CMAC_VERIFY);

    return 0;
}

