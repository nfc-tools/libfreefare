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
 */

#ifndef __FREEFARE_INTERNAL_H__
#define __FREEFARE_INTERNAL_H__

#include "config.h"

#include <openssl/des.h>

/*
 * Endienness macros
 *
 * POSIX does not describe any API for endianness problems, and solutions are
 * mostly vendor-dependant.  Some operating systems provide a complete
 * framework for this (FreeBSD, OpenBSD), some provide nothing in the base
 * system (Mac OS), GNU/Linux systems may or may not provide macros to do the
 * conversion depending on the version of the libc.
 *
 * This is a PITA but unfortunately we have no other solution than doing all
 * this gymnastic.  Depending of what is defined if one or more of endian.h,
 * sys/endian.h and byteswap.h was included, define a set of macros to stick to
 * the set of macros provided by FreeBSD (it's a historic choice: development
 * was done on this operating system when endianness problems first had to be
 * dealt with).
 */

#if !defined(le32toh) && defined(letoh32)
#  define le32toh(x) letoh32(x)
#  define be32toh(x) betoh32(x)
#endif

#if !defined(le16toh) && defined(letoh16)
#  define le16toh(x) letoh16(x)
#  define be16toh(x) betoh16(x)
#endif

#if !defined(le32toh) && defined(CFSwapInt32LittleToHost)
#  define be32toh(x) CFSwapInt32BigToHost(x)
#  define htobe32(x) CFSwapInt32HostToBig(x)
#  define le32toh(x) CFSwapInt32LittleToHost(x)
#  define htole32(x) CFSwapInt32HostToLittle(x)
#endif

#if !defined(le16toh) && defined(CFSwapInt16LittleToHost)
#  define be16toh(x) CFSwapInt16BigToHost(x)
#  define htobe16(x) CFSwapInt16HostToBig(x)
#  define le16toh(x) CFSwapInt16LittleToHost(x)
#  define htole16(x) CFSwapInt16HostToLittle(x)
#endif

#if !defined(le32toh) && defined(bswap_32)
#  if BYTE_ORDER == LITTLE_ENDIAN
#    define be32toh(x) bswap_32(x)
#    define htobe32(x) bswap_32(x)
#    define le32toh(x) (x)
#    define htole32(x) (x)
#  else
#    define be32toh(x) (x)
#    define htobe32(x) (x)
#    define le32toh(x) bswap_32(x)
#    define htole32(x) bswap_32(x)
#  endif
#endif

#if !defined(htole16) && defined(bswap_16)
#  if BYTE_ORDER == LITTLE_ENDIAN
#    define be16toh(x) (bswap_16(x))
#    define htobe16(x) (bswap_16(x))
#    define htole16(x) (x)
#    define le16toh(x) (x)
#  else
#    define be16toh(x) (x)
#    define htobe16(x) (x)
#    define htole16(x) (bswap_16(x))
#    define le16toh(x) (bswap_16(x))
#  endif
#endif

#define MIN(a, b) (((a) < (b)) ? (a) : (b))
#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define MAX_CRYPTO_BLOCK_SIZE 16

void		*memdup (const void *p, const size_t n);

struct mad_sector_0x00;
struct mad_sector_0x10;

void		 nxp_crc (uint8_t *crc, const uint8_t value);
FreefareTag	 mifare_classic_tag_new (void);
void		 mifare_classic_tag_free (FreefareTag tag);
FreefareTag	 mifare_desfire_tag_new (void);
void		 mifare_desfire_tag_free (FreefareTag tags);
FreefareTag	 mifare_ultralight_tag_new (void);
void		 mifare_ultralight_tag_free (FreefareTag tag);
uint8_t		 sector_0x00_crc8 (Mad mad);
uint8_t		 sector_0x10_crc8 (Mad mad);

typedef enum {
    MCD_SEND,
    MCD_RECEIVE
} MifareCryptoDirection;

typedef enum {
    MCO_ENCYPHER,
    MCO_DECYPHER
} MifareCryptoOperation;

#define MDCM_MASK 0x000F

#define CMAC_NONE 0

// Data send to the PICC is used to update the CMAC
#define CMAC_COMMAND 0x010
// Data received from the PICC is used to update the CMAC
#define CMAC_VERIFY  0x020

// MAC the command (when MDCM_MACED)
#define MAC_COMMAND 0x100
// The command returns a MAC to verify (when MDCM_MACED)
#define MAC_VERIFY  0x200

#define ENC_COMMAND 0x1000
#define NO_CRC      0x2000

#define MAC_MASK   0x0F0
#define CMAC_MACK  0xF00

void		*mifare_cryto_preprocess_data (FreefareTag tag, void *data, size_t *nbytes, off_t offset, int communication_settings);
void		*mifare_cryto_postprocess_data (FreefareTag tag, void *data, ssize_t *nbytes, int communication_settings);
void		 mifare_cypher_single_block (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size);
void		 mifare_cypher_blocks_chained (FreefareTag tag, MifareDESFireKey key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation);
void		 rol (uint8_t *data, const size_t len);
void		 desfire_crc32 (const uint8_t *data, const size_t len, uint8_t *crc);
void		 desfire_crc32_append (uint8_t *data, const size_t len);
size_t		 key_block_size (const MifareDESFireKey key);
size_t		 padded_data_length (const size_t nbytes, const size_t block_size);
size_t		 maced_data_length (const MifareDESFireKey key, const size_t nbytes);
size_t		 enciphered_data_length (const FreefareTag tag, const size_t nbytes, int communication_settings);

void		 cmac_generate_subkeys (MifareDESFireKey key);
void		 cmac (const MifareDESFireKey key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac);
void		*assert_crypto_buffer_size (FreefareTag tag, size_t nbytes);

#define MIFARE_ULTRALIGHT_PAGE_COUNT  0x10
#define MIFARE_ULTRALIGHT_C_PAGE_COUNT 0x30
#define MIFARE_ULTRALIGHT_C_PAGE_COUNT_READ 0x2C
// Max PAGE_COUNT of the Ultralight Family:
#define MIFARE_ULTRALIGHT_MAX_PAGE_COUNT 0x30

struct supported_tag {
    enum freefare_tag_type type;
    const char *friendly_name;
    uint8_t modulation_type;
    uint8_t SAK;
    uint8_t ATS_min_length;
    uint8_t ATS_compare_length;
    uint8_t ATS[5];
    bool (*check_tag_on_reader) (nfc_device *, nfc_iso14443a_info);
};

/*
 * This structure is common to all supported MIFARE targets but shall not be
 * used directly (it's some kind of abstract class).  All members in this
 * structure are initialized by freefare_get_tags().
 *
 * Extra members in derived classes are initialized in the correpsonding
 * mifare_*_connect() function.
 */
struct freefare_tag {
    nfc_device *device;
    nfc_target info;
    const struct supported_tag *tag_info;
    int active;
};

struct mifare_classic_tag {
    struct freefare_tag __tag;

    MifareClassicKeyType last_authentication_key_type;

    /*
     * The following block numbers are on 2 bytes in order to use invalid
     * address and avoid false cache hit with inconsistent data.
     */
    struct {
      int16_t sector_trailer_block_number;
      uint16_t sector_access_bits;
      int16_t block_number;
      uint8_t block_access_bits;
    } cached_access_bits;
};

struct mifare_desfire_aid {
    uint8_t data[3];
};

struct mifare_desfire_key {
    uint8_t data[24];
    enum {
	T_DES,
	T_3DES,
	T_3K3DES,
	T_AES
    } type;
    DES_key_schedule ks1;
    DES_key_schedule ks2;
    DES_key_schedule ks3;
    uint8_t cmac_sk1[24];
    uint8_t cmac_sk2[24];
    uint8_t aes_version;
};

struct mifare_desfire_tag {
    struct freefare_tag __tag;

    uint8_t last_picc_error;
    uint8_t last_internal_error;
    uint8_t last_pcd_error;
    MifareDESFireKey session_key;
    enum { AS_LEGACY, AS_NEW } authentication_scheme;
    uint8_t authenticated_key_no;
    uint8_t ivect[MAX_CRYPTO_BLOCK_SIZE];
    uint8_t cmac[16];
    uint8_t *crypto_buffer;
    size_t crypto_buffer_size;
    uint32_t selected_application;
};

MifareDESFireKey mifare_desfire_session_key_new (const uint8_t rnda[], const uint8_t rndb[], MifareDESFireKey authentication_key);
const char	*mifare_desfire_error_lookup (uint8_t error);

struct mifare_ultralight_tag {
    struct freefare_tag __tag;

    /* mifare_ultralight_read() reads 4 pages at a time (wrapping) */
    MifareUltralightPage cache[MIFARE_ULTRALIGHT_MAX_PAGE_COUNT + 3];
    uint8_t cached_pages[MIFARE_ULTRALIGHT_MAX_PAGE_COUNT];
};

/*
 * FreefareTag assertion macros
 *
 * This macros provide a simple and unified way to perform various tests at the
 * beginning of the different targets functions.
 */
#define ASSERT_ACTIVE(tag) do { if (!tag->active) return errno = ENXIO, -1; } while (0)
#define ASSERT_INACTIVE(tag) do { if (tag->active) return errno = ENXIO, -1; } while (0)

#define ASSERT_MIFARE_CLASSIC(tag) do { if ((tag->tag_info->type != MIFARE_CLASSIC_1K) && (tag->tag_info->type != MIFARE_CLASSIC_4K)) return errno = ENODEV, -1; } while (0)
#define ASSERT_MIFARE_DESFIRE(tag) do { if (tag->tag_info->type != MIFARE_DESFIRE) return errno = ENODEV, -1; } while (0)
#define IS_MIFARE_ULTRALIGHT_C(tag) (tag->tag_info->type == MIFARE_ULTRALIGHT_C)
#define ASSERT_MIFARE_ULTRALIGHT(tag) do { if ((tag->tag_info->type != MIFARE_ULTRALIGHT) && (! IS_MIFARE_ULTRALIGHT_C(tag))) return errno = ENODEV, -1; } while (0)
#define ASSERT_MIFARE_ULTRALIGHT_C(tag) do { if (! IS_MIFARE_ULTRALIGHT_C(tag)) return errno = ENODEV, -1; } while (0)

/* 
 * FreefareTag cast macros
 *
 * This macros are intended to provide a convenient way to cast abstract
 * FreefareTag structures to concrete Tags (e.g. MIFARE Classic tag).
 */
#define MIFARE_CLASSIC(tag) ((struct mifare_classic_tag *) tag)
#define MIFARE_DESFIRE(tag) ((struct mifare_desfire_tag *) tag)
#define MIFARE_ULTRALIGHT(tag) ((struct mifare_ultralight_tag *) tag)

/*
 * Access bits manipulation macros
 */
#define DB_AB(ab) ((ab == C_DEFAULT) ? C_000 : ab)
#define TB_AB(ab) ((ab == C_DEFAULT) ? C_100 : ab)

#ifdef WITH_DEBUG
#define DEBUG_FUNCTION() do { printf("*** \033[033;1m%s\033[0m ***\n", __FUNCTION__); } while (0)
#define DEBUG_XFER(data, nbytes, hint) do { hexdump (data, nbytes, hint, 0); } while (0)
#else
#define DEBUG_FUNCTION() do {} while (0)
#define DEBUG_XFER(data, nbytes, hint) do {} while (0)
#endif


/*
 * Buffer management macros.
 * 
 * The following macros ease setting-up and using buffers:
 * BUFFER_INIT (data, 5);      // data -> [ xx, xx, xx, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 0
 * BUFFER_APPEND (data, 0x12); // data -> [ 12, xx, xx, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 1
 * uint16_t x = 0x3456;        // We suppose we are little endian
 * BUFFER_APPEND_BYTES (data, x, 2);
 *                             // data -> [ 12, 56, 34, xx, xx ]
 * BUFFER_SIZE (data);         // size -> 3
 * BUFFER_APPEND_LE (data, x, 2, sizeof (x));
 *                             // data -> [ 12, 56, 34, 34, 56 ]
 * BUFFER_SIZE (data);         // size -> 5
 */

/*
 * Initialise a buffer named buffer_name of size bytes.
 */
#define BUFFER_INIT(buffer_name, size) \
    uint8_t buffer_name[size]; \
    size_t __##buffer_name##_size = size; \
    size_t __##buffer_name##_n = 0

/*
 * Create a wrapper for an existing buffer.
 * BEWARE!  It eats children!
 */
#define BUFFER_ALIAS(buffer_name, origin, origin_size) \
    uint8_t *buffer_name = (void *)origin; \
    size_t __##buffer_name##_size = origin_size; \
    size_t __##buffer_name##_n = 0;

#define BUFFER_SIZE(buffer_name) (__##buffer_name##_n)

#define BUFFER_MAXSIZE(buffer_name) (__##buffer_name##_size)

#define BUFFER_CLEAR(buffer_name) (__##buffer_name##_n = 0)
/*
 * Append one byte of data to the buffer buffer_name.
 */
#define BUFFER_APPEND(buffer_name, data) \
    do { \
	buffer_name[__##buffer_name##_n++] = data; \
    } while (0)

/*
 * Append size bytes of data to the buffer buffer_name.
 */
#define BUFFER_APPEND_BYTES(buffer_name, data, size) \
    do { \
	size_t __n = 0; \
	while (__n < size) { \
	    buffer_name[__##buffer_name##_n++] = ((uint8_t *)data)[__n++]; \
	} \
    } while (0)

/*
 * Append data_size bytes of data at the end of the buffer.  Since data is
 * copied as a little endian value, the storage size of the value has to be
 * passed as the field_size parameter.
 *
 * Example: to copy 24 bits of data from a 32 bits value:
 * BUFFER_APPEND_LE (buffer, data, 3, 4);
 */

#if defined(_BYTE_ORDER) && (_BYTE_ORDER != _LITTLE_ENDIAN)
#define BUFFER_APPEND_LE(buffer, data, data_size, field_size) \
    do { \
	size_t __data_size = data_size; \
	size_t __field_size = field_size; \
	while (__field_size--, __data_size--) { \
	    buffer[__##buffer##_n++] = ((uint8_t *)&data)[__field_size]; \
	} \
    } while (0)
#else
#define BUFFER_APPEND_LE(buffer, data, data_size, field_size) \
    do { \
	memcpy (buffer + __##buffer##_n, &data, data_size); \
	__##buffer##_n += data_size; \
    } while (0)
#endif

#endif /* !__FREEFARE_INTERNAL_H__ */
