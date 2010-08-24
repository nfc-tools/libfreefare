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

enum mifare_tag_type {
    ULTRALIGHT,
//    ULTRALIGHT_C,
//    MINI,
    CLASSIC_1K,
    CLASSIC_4K,
//    PLUS_S2K,
//    PLUS_S4K,
//    PLUS_X2K,
//    PLUS_X4K,
    DESFIRE
};

struct mifare_tag;
typedef struct mifare_tag *MifareTag;

typedef uint8_t MifareUltralightPageNumber;
typedef unsigned char MifareUltralightPage[4];

MifareTag	*freefare_get_tags (nfc_device_t *device);
enum mifare_tag_type freefare_get_tag_type (MifareTag tag);
const char	*freefare_get_tag_friendly_name (MifareTag tag);
char		*freefare_get_tag_uid (MifareTag tag);
void		 freefare_free_tag (MifareTag tag);
void		 freefare_free_tags (MifareTag *tags);

int		 mifare_ultralight_connect (MifareTag tag);
int		 mifare_ultralight_disconnect (MifareTag tag);

int		 mifare_ultralight_read (MifareTag tag, const MifareUltralightPageNumber page, MifareUltralightPage *data);
int		 mifare_ultralight_write (MifareTag tag, const MifareUltralightPageNumber page, const MifareUltralightPage data);

typedef unsigned char MifareClassicBlock[16];

typedef uint8_t MifareClassicSectorNumber;
typedef unsigned char MifareClassicBlockNumber;

typedef enum { MFC_KEY_A, MFC_KEY_B } MifareClassicKeyType;
typedef unsigned char MifareClassicKey[6];

/* NFC Forum public key */
extern const MifareClassicKey mifare_classic_nfcforum_public_key_a;

int		 mifare_classic_connect (MifareTag tag);
int		 mifare_classic_disconnect (MifareTag tag);

int		 mifare_classic_authenticate (MifareTag tag, const MifareClassicBlockNumber block, const MifareClassicKey key, const MifareClassicKeyType key_type);
int		 mifare_classic_read (MifareTag tag, const MifareClassicBlockNumber block, MifareClassicBlock *data);
int		 mifare_classic_init_value (MifareTag tag, const MifareClassicBlockNumber block, const int32_t value, const MifareClassicBlockNumber adr);
int		 mifare_classic_read_value (MifareTag tag, const MifareClassicBlockNumber block, int32_t *value, MifareClassicBlockNumber *adr);
int		 mifare_classic_write (MifareTag tag, const MifareClassicBlockNumber block, const MifareClassicBlock data);

int		 mifare_classic_increment (MifareTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_decrement (MifareTag tag, const MifareClassicBlockNumber block, const uint32_t amount);
int		 mifare_classic_restore (MifareTag tag, const MifareClassicBlockNumber block);
int		 mifare_classic_transfer (MifareTag tag, const MifareClassicBlockNumber block);

int 		 mifare_classic_get_trailer_block_permission (MifareTag tag, const MifareClassicBlockNumber block, const uint16_t permission, const MifareClassicKeyType key_type);
int		 mifare_classic_get_data_block_permission (MifareTag tag, const MifareClassicBlockNumber block, const unsigned char permission, const MifareClassicKeyType key_type);

int		 mifare_classic_format_sector (MifareTag tag, const MifareClassicSectorNumber sector);

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
Mad		 mad_read (MifareTag tag);
int		 mad_write (MifareTag tag, Mad mad, const MifareClassicKey key_b_sector_00, const MifareClassicKey key_b_sector_10);
int		 mad_get_version (Mad mad);
void		 mad_set_version (Mad mad, const uint8_t version);
MifareClassicSectorNumber mad_get_card_publisher_sector (Mad mad);
int		 mad_set_card_publisher_sector (Mad mad, const MifareClassicSectorNumber cps);
int		 mad_get_aid (Mad mad, const MifareClassicSectorNumber sector, MadAid *aid);
int		 mad_set_aid (Mad mad, const MifareClassicSectorNumber sector, MadAid aid);
bool		 mad_sector_reserved (const MifareClassicSectorNumber sector);
void		 mad_free (Mad mad);

MifareClassicSectorNumber *mifare_application_alloc (Mad mad, const MadAid aid, const size_t size);
ssize_t		 mifare_application_read (MifareTag tag, Mad mad, const MadAid aid, void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type);
ssize_t		 mifare_application_write (MifareTag tag, Mad mad, const MadAid aid, const void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type);
void		 mifare_application_free (Mad mad, const MadAid aid);

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

#define MDCM_PLAIN   0x00
#define MDCM_MACING  0x01
#define MDCM_FULLDES 0x03

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

#define MDAD_KEY0  0x0
#define MDAD_KEY1  0x1
#define MDAD_KEY2  0x2
#define MDAD_KEY3  0x3
#define MDAD_KEY4  0x4
#define MDAD_KEY5  0x5
#define MDAD_KEY6  0x6
#define MDAD_KEY7  0x7
#define MDAD_KEY8  0x8
#define MDAD_KEY9  0x9
#define MDAD_KEY10 0xa
#define MDAD_KEY11 0xb
#define MDAD_KEY12 0xc
#define MDAD_KEY13 0xd
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

struct mifare_desfire_aid;
typedef struct mifare_desfire_aid *MifareDESFireAID;

MifareDESFireAID mifare_desfire_aid_new (uint8_t application_code, uint8_t function_cluster_code, uint8_t n);
MifareDESFireAID mifare_desfire_aid_new_with_mad_aid (MadAid mad_aid, uint8_t n);

struct mifare_desfire_key;
typedef struct mifare_desfire_key *MifareDESFireKey;

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

int		 mifare_desfire_connect (MifareTag tag);
int		 mifare_desfire_disconnect (MifareTag tag);
uint8_t	 	 mifare_desfire_get_last_error (MifareTag tag);

int		 mifare_desfire_authenticate (MifareTag tag, uint8_t key_no, MifareDESFireKey key);
int		 mifare_desfire_change_key_settings (MifareTag tag, uint8_t settings);
int		 mifare_desfire_get_key_settings (MifareTag tag, uint8_t *settings, uint8_t *max_keys);
int		 mifare_desfire_change_key (MifareTag tag, uint8_t key_no, MifareDESFireKey new_key, MifareDESFireKey old_key);
int		 mifare_desfire_get_key_version (MifareTag tag, uint8_t key_no, uint8_t *version);
int		 mifare_desfire_create_application (MifareTag tag, MifareDESFireAID aid, uint8_t settings, uint8_t key_no);
int		 mifare_desfire_delete_application (MifareTag tag, MifareDESFireAID aid);
int		 mifare_desfire_get_application_ids (MifareTag tag, MifareDESFireAID *aids[], size_t *count);
void		 mifare_desfire_free_application_ids (MifareDESFireAID aids[]);
int		 mifare_desfire_select_application (MifareTag tag, MifareDESFireAID aid);
int		 mifare_desfire_format_picc (MifareTag tag);
int		 mifare_desfire_get_version (MifareTag tag, struct mifare_desfire_version_info *version_info);
int		 mifare_desfire_get_file_ids (MifareTag tag, uint8_t *files[], size_t *count);
int		 mifare_desfire_get_file_settings (MifareTag tag, uint8_t file_no, struct mifare_desfire_file_settings *settings);
int		 mifare_desfire_change_file_settings (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights);
int		 mifare_desfire_create_std_data_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
int		 mifare_desfire_create_backup_data_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t file_size);
int		 mifare_desfire_create_value_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, int32_t lower_limit, int32_t upper_limit, int32_t value, uint8_t limited_credit_enable);
int		 mifare_desfire_create_linear_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
int		 mifare_desfire_create_cyclic_record_file (MifareTag tag, uint8_t file_no, uint8_t communication_settings, uint16_t access_rights, uint32_t record_size, uint32_t max_number_of_records);
int		 mifare_desfire_delete_file (MifareTag tag, uint8_t file_no);

ssize_t		 mifare_desfire_read_data (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_read_data_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
ssize_t		 mifare_desfire_write_data (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_write_data_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
int		 mifare_desfire_get_value (MifareTag tag, uint8_t file_no, int32_t *value);
int		 mifare_desfire_get_value_ex (MifareTag tag, uint8_t file_no, int32_t *value, int cs);
int		 mifare_desfire_credit (MifareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_credit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs);
int		 mifare_desfire_debit (MifareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_debit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs);
int		 mifare_desfire_limited_credit (MifareTag tag, uint8_t file_no, int32_t amount);
int		 mifare_desfire_limited_credit_ex (MifareTag tag, uint8_t file_no, int32_t amount, int cs);
ssize_t		 mifare_desfire_write_record (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_write_record_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
ssize_t		 mifare_desfire_read_records (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data);
ssize_t		 mifare_desfire_read_records_ex (MifareTag tag, uint8_t file_no, off_t offset, size_t length, void *data, int cs);
int		 mifare_desfire_clear_record_file (MifareTag tag, uint8_t file_no);
int		 mifare_desfire_commit_transaction (MifareTag tag);
int		 mifare_desfire_abort_transaction (MifareTag tag);

MifareDESFireKey mifare_desfire_des_key_new (uint8_t value[8]);
MifareDESFireKey mifare_desfire_3des_key_new (uint8_t value[16]);
MifareDESFireKey mifare_desfire_des_key_new_with_version (uint8_t value[8]);
MifareDESFireKey mifare_desfire_3des_key_new_with_version (uint8_t value[16]);
uint8_t		 mifare_desfire_key_get_version (MifareDESFireKey key);
void		 mifare_desfire_key_set_version (MifareDESFireKey key, uint8_t version);
void		 mifare_desfire_key_free (MifareDESFireKey key);

const char	*desfire_error_lookup (uint8_t error);

uint8_t		*tlv_encode (const uint8_t type, const uint8_t *istream, uint16_t isize, size_t *osize);
uint8_t		*tlv_decode (const uint8_t *istream, uint8_t *type, uint16_t *size);
uint8_t		*tlv_append (uint8_t *a, uint8_t *b);

#ifdef __cplusplus
    }
#endif // __cplusplus

#endif /* !__FREEFARE_H__ */
