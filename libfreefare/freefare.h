/*-
 * Copyright (C) 2009, 2010, Romain Tartiere, Romuald Conty.
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

#ifndef __FREEFARE_H__
#define __FREEFARE_H__

#include <sys/types.h>

#include <stdint.h>

#include <nfc/nfc.h>

#ifdef __cplusplus
    extern "C" {
#endif // __cplusplus

enum freefare_tag_type {
    ULTRALIGHT,
    ULTRALIGHT_C,
//    MINI,
    CLASSIC_1K,
    CLASSIC_4K,
//    PLUS_S2K,
//    PLUS_S4K,
//    PLUS_X2K,
//    PLUS_X4K,
    DESFIRE
};

struct freefare_tag;
typedef struct freefare_tag *FreefareTag;

/* Replace any MifareTag by the generic FreefareTag. */
typedef struct freefare_tag *MifareTag __attribute__ ((deprecated));

struct mifare_desfire_key;
typedef struct mifare_desfire_key *MifareDESFireKey;

typedef uint8_t MifareUltralightPageNumber;
typedef unsigned char MifareUltralightPage[4];

FreefareTag	*freefare_get_tags (nfc_device *device);
FreefareTag	 freefare_tag_new (nfc_device *device, nfc_iso14443a_info nai);
enum freefare_tag_type freefare_get_tag_type (FreefareTag tag);
const char	*freefare_get_tag_friendly_name (FreefareTag tag);
char		*freefare_get_tag_uid (FreefareTag tag);
void		 freefare_free_tag (FreefareTag tag);
void		 freefare_free_tags (FreefareTag *tags);
bool		 freefare_selected_tag_is_present(nfc_device *device);

const char	*freefare_strerror (FreefareTag tag);
int		 freefare_strerror_r (FreefareTag tag, char *buffer, size_t len);
void		 freefare_perror (FreefareTag tag, const char *string);

int		 mifare_ultralight_connect (FreefareTag tag);
int		 mifare_ultralight_disconnect (FreefareTag tag);

int		 mifare_ultralight_read (FreefareTag tag, const MifareUltralightPageNumber page, MifareUltralightPage *data);
int		 mifare_ultralight_write (FreefareTag tag, const MifareUltralightPageNumber page, const MifareUltralightPage data);

int		 mifare_ultralightc_authenticate (FreefareTag tag, const MifareDESFireKey key);
bool		 is_mifare_ultralightc_on_reader (nfc_device *device, nfc_iso14443a_info nai);

typedef unsigned char MifareClassicBlock[16];

typedef uint8_t MifareClassicSectorNumber;
typedef unsigned char MifareClassicBlockNumber;

typedef enum { MFC_KEY_A, MFC_KEY_B } MifareClassicKeyType;
typedef unsigned char MifareClassicKey[6];

/* NFC Forum public key */
extern const MifareClassicKey mifare_classic_nfcforum_public_key_a;

int		 mifare_classic_connect (FreefareTag tag);
int		 mifare_classic_disconnect (FreefareTag tag);

int		 mifare_classic_authenticate (FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type);
int		 mifare_classic_read (FreefareTag tag, const MifareClassicBlockNumber block, MifareClassicBlock *data);
int		 mifare_classic_init_value (FreefareTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr);
int		 mifare_classic_read_value (FreefareTag tag, const MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr);
int		 mifare_classic_write (FreefareTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data);

int		 mifare_classic_increment (FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_decrement (FreefareTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_restore (FreefareTag tag, const MifareClassicBlockNumber block);
int		 mifare_classic_transfer (FreefareTag tag, const MifareClassicBlockNumber block);

int 		 mifare_classic_get_trailer_block_permission (FreefareTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type);
int		 mifare_classic_get_data_block_permission (FreefareTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type);

int		 mifare_classic_format_sector (FreefareTag tag, const MifareClassicSectorNumber sector);

void		 mifare_classic_trailer_block (MifareClassicBlock *block, const MifareClassicKey key_a, uint8_t ab_0, uint8_t ab_1, uint8_t ab_2, uint8_t ab_tb, const uint8_t gpb, const MifareClassicKey key_b);

MifareClassicSectorNumber mifare_classic_block_sector (MifareClassicBlockNumber block);
MifareClassicBlockNumber  mifare_classic_sector_first_block (MifareClassicSectorNumber sector);
size_t		 mifare_classic_sector_block_count (MifareClassicSectorNumber sector);
MifareClassicBlockNumber  mifare_classic_sector_last_block (MifareClassicSectorNumber sector);

#define C_000 0
#define C_001 1
#define C_010 2
#define C_011 3
#define C_100 4
#define C_101 5
#define C_110 6
#define C_111 7
#define C_DEFAULT 255

/* MIFARE Classic Access Bits */
#define MCAB_R 0x8
#define MCAB_W 0x4
#define MCAB_D 0x2
#define MCAB_I 0x1

#define MCAB_READ_KEYA         0x400
#define MCAB_WRITE_KEYA        0x100
#define MCAB_READ_ACCESS_BITS  0x040
#define MCAB_WRITE_ACCESS_BITS 0x010
#define MCAB_READ_KEYB         0x004
#define MCAB_WRITE_KEYB        0x001

struct mad_aid {
    uint8_t application_code;
    uint8_t function_cluster_code;
};
typedef struct mad_aid MadAid;

struct mad;
typedef struct mad *Mad;

/* MAD Public read key A */
extern const MifareClassicKey mad_public_key_a;

/* AID - Adminisration codes */
extern const MadAid mad_free_aid;
extern const MadAid mad_defect_aid;
extern const MadAid mad_reserved_aid;
extern const MadAid mad_card_holder_aid;
extern const MadAid mad_not_applicable_aid;

/* NFC Forum AID */
extern const MadAid mad_nfcforum_aid;

Mad		 mad_new (const uint8_t version);
Mad		 mad_read (FreefareTag tag);
int		 mad_write (FreefareTag tag, Mad mad, const MifareClassicKey key_b_sector_00, const MifareClassicKey key_b_sector_10);
int		 mad_get_version (Mad mad);
void		 mad_set_version (Mad mad, const uint8_t version);
MifareClassicSectorNumber mad_get_card_publisher_sector (Mad mad);
int		 mad_set_card_publisher_sector (Mad mad, const MifareClassicSectorNumber cps);
int		 mad_get_aid (Mad mad, const MifareClassicSectorNumber sector, MadAid *aid);
int		 mad_set_aid (Mad mad, const MifareClassicSectorNumber sector, MadAid aid);
bool		 mad_sector_reserved (const MifareClassicSectorNumber sector);
void		 mad_free (Mad mad);

MifareClassicSectorNumber *mifare_application_alloc (Mad mad, const MadAid aid, const size_t size);
ssize_t		 mifare_application_read (FreefareTag tag, Mad mad, const MadAid aid, void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type);
ssize_t		 mifare_application_write (FreefareTag tag, Mad mad, const MadAid aid, const void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type);
int		 mifare_application_free (Mad mad, const MadAid aid);

MifareClassicSectorNumber *mifare_application_find (Mad mad, const MadAid aid);

/* File types */

enum mifare_desfire_file_types {
    MDFT_STANDARD_DATA_FILE             = 0x00,
    MDFT_BACKUP_DATA_FILE               = 0x01,
    MDFT_VALUE_FILE_WITH_BACKUP         = 0x02,
    MDFT_LINEAR_RECORD_FILE_WITH_BACKUP = 0x03,
    MDFT_CYCLIC_RECORD_FILE_WITH_BACKUP = 0x04
};

/* Communication mode */

#define MDCM_PLAIN      0x00
#define MDCM_MACED      0x01
#define MDCM_ENCIPHERED 0x03

/* Mifare DESFire EV1 Application crypto operations */

#define APPLICATION_CRYPTO_DES    0x00
#define APPLICATION_CRYPTO_3K3DES 0x40
#define APPLICATION_CRYPTO_AES    0x80

/* Access right */

#define MDAR(read,write,read_write,change_access_rights) ( \
	(read << 12) | \
	(write << 8) | \
	(read_write << 4) | \
	(change_access_rights) \
	)
#define MDAR_READ(ar)       (((ar) >> 12) & 0x0f)
#define MDAR_WRITE(ar)      (((ar) >>  8) & 0x0f)
#define MDAR_READ_WRITE(ar) (((ar) >>  4) & 0x0f)
#define MDAR_CHANGE_AR(ar)  ((ar)         & 0x0f)

#define MDAR_KEY0  0x0
#define MDAR_KEY1  0x1
#define MDAR_KEY2  0x2
#define MDAR_KEY3  0x3
#define MDAR_KEY4  0x4
#define MDAR_KEY5  0x5
#define MDAR_KEY6  0x6
#define MDAR_KEY7  0x7
#define MDAR_KEY8  0x8
#define MDAR_KEY9  0x9
#define MDAR_KEY10 0xa
#define MDAR_KEY11 0xb
#define MDAR_KEY12 0xc
#define MDAR_KEY13 0xd
#define MDAR_FREE  0xE
#define MDAR_DENY  0xF

/* Status and error codes */

#define	OPERATION_OK		0x00
#define	NO_CHANGES		0x0C
#define	OUT_OF_EEPROM_ERROR	0x0E
#define	ILLEGAL_COMMAND_CODE	0x1C
#define	INTEGRITY_ERROR		0x1E
#define	NO_SUCH_KEY		0x40
#define	LENGTH_ERROR		0x7E
#define	PERMISSION_ERROR	0x9D
#define	PARAMETER_ERROR		0x9E
#define	APPLICATION_NOT_FOUND	0xA0
#define	APPL_INTEGRITY_ERROR	0xA1
#define	AUTHENTICATION_ERROR	0xAE
#define	ADDITIONAL_FRAME	0xAF
#define	BOUNDARY_ERROR		0xBE
#define	PICC_INTEGRITY_ERROR	0xC1
#define	COMMAND_ABORTED		0xCA
#define	PICC_DISABLED_ERROR	0xCD
#define	COUNT_ERROR		0xCE
#define	DUPLICATE_ERROR		0xDE
#define	EEPROM_ERROR		0xEE
#define	FILE_NOT_FOUND		0xF0
#define	FILE_INTEGRITY_ERROR	0xF1

/* Error code managed by the library */

#define CRYPTO_ERROR            0x01

struct mifare_desfire_aid;
typedef struct mifare_desfire_aid *MifareDESFireAID;

struct mifare_desfire_df {
    uint32_t aid;
    uint16_t fid;
    uint8_t df_name[16];
    size_t df_name_len;
};
typedef struct mifare_desfire_df MifareDESFireDF;

MifareDESFireAID mifare_desfire_aid_new (uint32_t aid);
MifareDESFireAID mifare_desfire_aid_new_with_mad_aid (MadAid mad_aid, uint8_t n);
uint32_t	 mifare_desfire_aid_get_aid (MifareDESFireAID aid);

uint8_t		 mifare_desfire_last_pcd_error (FreefareTag tag);
uint8_t		 mifare_desfire_last_picc_error (FreefareTag tag);

#pragma pack (push)
#pragma pack (1)
struct mifare_desfire_version_info {
    struct {
	uint8_t vendor_id;
	uint8_t type;
	uint8_t subtype;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t storage_size;
	uint8_t protocol;
    } hardware;
    struct {
	uint8_t vendor_id;
	uint8_t type;
	uint8_t subtype;
	uint8_t version_major;
	uint8_t version_minor;
	uint8_t storage_size;
	uint8_t protocol;
    } software;
    uint8_t uid[7];
    uint8_t batch_number[5];
    uint8_t production_week;
    uint8_t production_year;
};
#pragma pack (pop)

struct mifare_desfire_file_settings {
    uint8_t file_type;
    uint8_t communication_settings;
    uint16_t access_rights;
    union {
	struct {
	    uint32_t file_size;
	} standard_file;
	struct {
	    int32_t lower_limit;
	    int32_t upper_limit;
	    int32_t limited_credit_value;
	    uint8_t limited_credit_enabled;
	} value_file;
	struct {
	    uint32_t record_size;
	    uint32_t max_number_of_records;
	    uint32_t current_number_of_records;
	} linear_record_file;
    } settings;
};

int		 mifare_desfire_connect (FreefareTag tag);
int		 mifare_desfire_disconnect (FreefareTag tag);

int		 mifare_desfire_authenticate (FreefareTag tag, uint8_t key_no, MifareDESFireKey key);
int		 mifare_desfire_authenticate_iso (FreefareTag tag, uint8_t key_no, MifareDESFireKey key);
int		 mifare_desfire_authenticate_aes (FreefareTag tag, uint8_t key_no, MifareDESFireKey key);
int		 mifare_desfire_change_key_settings (FreefareTag tag, uint8_t settings);
int		 mifare_desfire_get_key_settings (FreefareTag tag, uint8_t *settings, uint8_t *max_keys);
int		 mifare_desfire_change_key (FreefareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key);
int		 mifare_desfire_get_key_version (FreefareTag tag, uint8_t key_no, uint8_t *version);
int		 mifare_desfire_create_application (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no);
int		 mifare_desfire_create_application_3k3des (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no);
int		 mifare_desfire_create_application_aes (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no);

int		 mifare_desfire_create_application_iso (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t *iso_file_name, size_t iso_file_name_len);
int		 mifare_desfire_create_application_3k3des_iso (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t *iso_file_name, size_t iso_file_name_len);
int		 mifare_desfire_create_application_aes_iso (FreefareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no, int want_iso_file_identifiers, uint16_t iso_file_id, uint8_t *iso_file_name, size_t iso_file_name_len);

int		 mifare_desfire_delete_application (FreefareTag tag, MifareDESFireAID aid);
int		 mifare_desfire_get_application_ids (FreefareTag tag, MifareDESFireAID *aids[], size_t *count);
int		 mifare_desfire_get_df_names (FreefareTag tag, MifareDESFireDF *dfs[], size_t *count);
void		 mifare_desfire_free_application_ids (MifareDESFireAID aids[]);
int		 mifare_desfire_select_application (FreefareTag tag, MifareDESFireAID aid);
int		 mifare_desfire_format_picc (FreefareTag tag);
int		 mifare_desfire_get_version (FreefareTag tag, struct mifare_desfire_version_info *version_info);
int		 mifare_desfire_free_mem (FreefareTag tag, uint32_t *size);
int		 mifare_desfire_set_configuration (FreefareTag tag, bool disable_format, bool enable_random_uid);
int		 mifare_desfire_set_default_key (FreefareTag tag, MifareDESFireKey key);
int		 mifare_desfire_set_ats (FreefareTag tag, uint8_t *ats);
int		 mifare_desfire_get_card_uid (FreefareTag tag, char **uid);
int		 mifare_desfire_get_file_ids (FreefareTag tag, uint8_t **files, size_t *count);
int		 mifare_desfire_get_iso_file_ids (FreefareTag tag, uint16_t **files, size_t *count);
int		 mifare_desfire_get_file_settings (FreefareTag tag, uint8_t file_no, struct mifare_desfire_file_settings *settings);
int		 mifare_desfire_change_file_settings (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights);
int		 mifare_desfire_create_std_data_file (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
int		 mifare_desfire_create_std_data_file_iso (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size, uint16_t iso_file_id);
int		 mifare_desfire_create_backup_data_file (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
int		 mifare_desfire_create_backup_data_file_iso (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size, uint16_t iso_file_id);
int		 mifare_desfire_create_value_file (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit_enable);
int		 mifare_desfire_create_linear_record_file (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
int		 mifare_desfire_create_linear_record_file_iso (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records, uint16_t iso_file_id);
int		 mifare_desfire_create_cyclic_record_file (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
int		 mifare_desfire_create_cyclic_record_file_iso (FreefareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records, uint16_t iso_file_id);
int		 mifare_desfire_delete_file (FreefareTag tag, uint8_t file_no);

ssize_t		 mifare_desfire_read_data (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_read_data_ex (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
ssize_t		 mifare_desfire_write_data (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, const void *data);
ssize_t		 mifare_desfire_write_data_ex (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, const void *data, int cs);
int		 mifare_desfire_get_value (FreefareTag tag, uint8_t file_no, int32_t *value);
int		 mifare_desfire_get_value_ex (FreefareTag tag, uint8_t file_no, int32_t *value, int cs);
int		 mifare_desfire_credit (FreefareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_credit_ex (FreefareTag tag, uint8_t file_no, int32_t amount, int cs);
int		 mifare_desfire_debit (FreefareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_debit_ex (FreefareTag tag, uint8_t file_no, int32_t amount, int cs);
int		 mifare_desfire_limited_credit (FreefareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_limited_credit_ex (FreefareTag tag, uint8_t file_no, int32_t amount, int cs);
ssize_t		 mifare_desfire_write_record (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_write_record_ex (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
ssize_t		 mifare_desfire_read_records (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_read_records_ex (FreefareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
int		 mifare_desfire_clear_record_file (FreefareTag tag, uint8_t file_no);
int		 mifare_desfire_commit_transaction (FreefareTag tag);
int		 mifare_desfire_abort_transaction (FreefareTag tag);

MifareDESFireKey mifare_desfire_des_key_new (const uint8_t value[8]);
MifareDESFireKey mifare_desfire_3des_key_new (const uint8_t value[16]);
MifareDESFireKey mifare_desfire_des_key_new_with_version (const uint8_t value[8]);
MifareDESFireKey mifare_desfire_3des_key_new_with_version (const uint8_t value[16]);
MifareDESFireKey mifare_desfire_3k3des_key_new (const uint8_t value[24]);
MifareDESFireKey mifare_desfire_3k3des_key_new_with_version (const uint8_t value[24]);
MifareDESFireKey mifare_desfire_aes_key_new (const uint8_t value[16]);
MifareDESFireKey mifare_desfire_aes_key_new_with_version (const uint8_t value[16], uint8_t version);
uint8_t		 mifare_desfire_key_get_version (MifareDESFireKey key);
void		 mifare_desfire_key_set_version (MifareDESFireKey key, uint8_t version);
void		 mifare_desfire_key_free (MifareDESFireKey key);

uint8_t		*tlv_encode (const uint8_t type, const uint8_t *istream, uint16_t isize, size_t *osize);
uint8_t		*tlv_decode (const uint8_t *istream, uint8_t *type, uint16_t *size);
size_t		tlv_record_length (const uint8_t *istream, size_t *field_length_size, size_t *field_value_size);
uint8_t		*tlv_append (uint8_t *a, uint8_t *b);

#ifdef __cplusplus
    }
#endif // __cplusplus

#endif /* !__FREEFARE_H__ */
