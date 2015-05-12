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
 */

/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * NIST Special Publication 800-38B
 * Recommendation for Block Cipher Modes of Operation: The CMAC Mode for Authentication
 * May 2005
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


#if defined(HAVE_SYS_TYPES_H)
#  include <sys/types.h>
#endif

#include <openssl/aes.h>
#include <openssl/des.h>

#include <err.h>
#include <string.h>
#include <strings.h>

#ifdef WITH_DEBUG
#  include <libutil.h>
#endif

#include <freefare.h>
#include "freefare_internal.h"

#define MAC_LENGTH 4
#define CMAC_LENGTH 8

static void	 xor (const uint8_t *ivect, uint8_t *data, const size_t len);
static void	 desfire_crc32_byte (uint32_t *crc, const uint8_t value);
static size_t	 key_macing_length (MifareDESFireKey key);

static void
xor (const uint8_t *ivect, uint8_t *data, const size_t len)
{
    for (size_t i = 0; i < len; i++) {
	data[i] ^= ivect[i];
    }
}

void
rol (uint8_t *data, const size_t len)
{
    uint8_t first = data[0];
    for (size_t i = 0; i < len-1; i++) {
	data[i] = data[i+1];
    }
    data[len-1] = first;
}

void
lsl (uint8_t *data, size_t len)
{
    for (size_t n = 0; n < len - 1; n++) {
	data[n] = (data[n] << 1) | (data[n+1] >> 7);
    }
    data[len - 1] <<= 1;
}

void
cmac_generate_subkeys (MifareDESFireKey key)
{
    int kbs = key_block_size (key);
    const uint8_t R = (kbs == 8) ? 0x1B : 0x87;

    uint8_t l[kbs];
    memset (l, 0, kbs);

    uint8_t ivect[kbs];
    memset (ivect, 0, kbs);

    mifare_cypher_blocks_chained (NULL, key, ivect, l, kbs, MCD_RECEIVE, MCO_ENCYPHER);

    bool xor = false;

    // Used to compute CMAC on complete blocks
    memcpy (key->cmac_sk1, l, kbs);
    xor = l[0] & 0x80;
    lsl (key->cmac_sk1, kbs);
    if (xor)
	key->cmac_sk1[kbs-1] ^= R;

    // Used to compute CMAC on the last block if non-complete
    memcpy (key->cmac_sk2, key->cmac_sk1, kbs);
    xor = key->cmac_sk1[0] & 0x80;
    lsl (key->cmac_sk2, kbs);
    if (xor)
	key->cmac_sk2[kbs-1] ^= R;
}

void
cmac (const MifareDESFireKey key, uint8_t *ivect, const uint8_t *data, size_t len, uint8_t *cmac)
{
    int kbs = key_block_size (key);
    uint8_t *buffer = malloc (padded_data_length (len, kbs));

    if (!buffer)
	abort();

    memcpy (buffer, data, len);

    if ((!len) || (len % kbs)) {
	buffer[len++] = 0x80;
	while (len % kbs) {
	    buffer[len++] = 0x00;
	}
	xor (key->cmac_sk2, buffer + len - kbs, kbs);
    } else {
	xor (key->cmac_sk1, buffer + len - kbs, kbs);
    }

    mifare_cypher_blocks_chained (NULL, key, ivect, buffer, len, MCD_SEND, MCO_ENCYPHER);

    memcpy (cmac, ivect, kbs);

    free (buffer);
}

#define CRC32_PRESET 0xFFFFFFFF

static void
desfire_crc32_byte (uint32_t *crc, const uint8_t value)
{
    /* x32 + x26 + x23 + x22 + x16 + x12 + x11 + x10 + x8 + x7 + x5 + x4 + x2 + x + 1 */
    const uint32_t poly = 0xEDB88320;

    *crc ^= value;
    for (int current_bit = 7; current_bit >= 0; current_bit--) {
	int bit_out = (*crc) & 0x00000001;
	*crc >>= 1;
	if (bit_out)
	    *crc ^= poly;
    }
}

void
desfire_crc32 (const uint8_t *data, const size_t len, uint8_t *crc)
{
    uint32_t desfire_crc = CRC32_PRESET;
    for (size_t i = 0; i < len; i++) {
	desfire_crc32_byte (&desfire_crc, data[i]);
    }

    *((uint32_t *)(crc)) = htole32 (desfire_crc);
}

void
desfire_crc32_append (uint8_t *data, const size_t len)
{
    desfire_crc32 (data, len, data + len);
}

size_t
key_block_size (const MifareDESFireKey key)
{
    size_t block_size;

    switch (key->type) {
    case T_DES:
    case T_3DES:
    case T_3K3DES:
	block_size = 8;
	break;
    case T_AES:
	block_size = 16;
	break;
    }

    return block_size;
}

/*
 * Size of MACing produced with the key.
 */
static size_t
key_macing_length (const MifareDESFireKey key)
{
    size_t mac_length;

    switch (key->type) {
    case T_DES:
    case T_3DES:
	mac_length = MAC_LENGTH;
	break;
    case T_3K3DES:
    case T_AES:
	mac_length = CMAC_LENGTH;
	break;
    }

    return mac_length;
}

/*
 * Size required to store nbytes of data in a buffer of size n*block_size.
 */
size_t
padded_data_length (const size_t nbytes, const size_t block_size)
{
    if ((!nbytes) || (nbytes % block_size))
	return ((nbytes / block_size) + 1) * block_size;
    else
	return nbytes;
}

/*
 * Buffer size required to MAC nbytes of data
 */
size_t
maced_data_length (const MifareDESFireKey key, const size_t nbytes)
{
    return nbytes + key_macing_length (key);
}
/*
 * Buffer size required to encipher nbytes of data and a two bytes CRC.
 */
size_t
enciphered_data_length (const FreefareTag tag, const size_t nbytes, int communication_settings)
{
    size_t crc_length = 0;
    if (!(communication_settings & NO_CRC)) {
	switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	case AS_LEGACY:
	    crc_length = 2;
	    break;
	case AS_NEW:
	    crc_length = 4;
	    break;
	}
    }

    size_t block_size = MIFARE_DESFIRE(tag)->session_key ? key_block_size (MIFARE_DESFIRE (tag)->session_key) : 1;

    return padded_data_length (nbytes + crc_length, block_size);
}


/*
 * Ensure that tag's crypto buffer is large enough to store nbytes of data.
 */
void *
assert_crypto_buffer_size (FreefareTag tag, size_t nbytes)
{
    void *res = MIFARE_DESFIRE (tag)->crypto_buffer;
    if (MIFARE_DESFIRE (tag)->crypto_buffer_size < nbytes) {
	if ((res = realloc (MIFARE_DESFIRE (tag)->crypto_buffer, nbytes))) {
	    MIFARE_DESFIRE (tag)->crypto_buffer = res;
	    MIFARE_DESFIRE (tag)->crypto_buffer_size = nbytes;
	}
    }
    return res;
}

void *
mifare_cryto_preprocess_data (FreefareTag tag, void *data, size_t *nbytes, off_t offset, int communication_settings)
{
    uint8_t *res = data;
    uint8_t mac[4];
    size_t edl, mdl;
    bool append_mac = true;
    MifareDESFireKey key = MIFARE_DESFIRE (tag)->session_key;

    if (!key)
	return data;

    switch (communication_settings & MDCM_MASK) {
    case MDCM_PLAIN:
	if (AS_LEGACY == MIFARE_DESFIRE (tag)->authentication_scheme)
	    break;

	/*
	 * When using new authentication methods, PLAIN data transmission from
	 * the PICC to the PCD are CMACed, so we have to maintain the
	 * cryptographic initialisation vector up-to-date to check data
	 * integrity later.
	 *
	 * The only difference with CMACed data transmission is that the CMAC
	 * is not apended to the data send by the PCD to the PICC.
	 */

	append_mac = false;

	/* pass through */
    case MDCM_MACED:
	switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	case AS_LEGACY:
	    if (!(communication_settings & MAC_COMMAND))
		break;

	    /* pass through */
	    edl = padded_data_length (*nbytes - offset, key_block_size (MIFARE_DESFIRE (tag)->session_key)) + offset;
	    if (!(res = assert_crypto_buffer_size (tag, edl)))
		abort();

	    // Fill in the crypto buffer with data ...
	    memcpy (res, data, *nbytes);
	    // ... and 0 padding
	    memset (res + *nbytes, 0, edl - *nbytes);

	    mifare_cypher_blocks_chained (tag, NULL, NULL, res + offset, edl - offset, MCD_SEND, MCO_ENCYPHER);

	    memcpy (mac, res + edl - 8, 4);

	    // Copy again provided data (was overwritten by mifare_cypher_blocks_chained)
	    memcpy (res, data, *nbytes);

	    if (!(communication_settings & MAC_COMMAND))
		break;
	    // Append MAC
	    mdl = maced_data_length (MIFARE_DESFIRE (tag)->session_key, *nbytes - offset) + offset;
	    if (!(res = assert_crypto_buffer_size (tag, mdl)))
		abort();

	    memcpy (res + *nbytes, mac, 4);

	    *nbytes += 4;
	    break;
	case AS_NEW:
	    if (!(communication_settings & CMAC_COMMAND))
		break;
	    cmac (key, MIFARE_DESFIRE (tag)->ivect, res, *nbytes, MIFARE_DESFIRE (tag)->cmac);

	    if (append_mac) {
		mdl = maced_data_length (key, *nbytes);
		if (!(res = assert_crypto_buffer_size (tag, mdl)))
		    abort();

		memcpy (res, data, *nbytes);
		memcpy (res + *nbytes, MIFARE_DESFIRE (tag)->cmac, CMAC_LENGTH);
		*nbytes += CMAC_LENGTH;
	    }
	    break;
	}

	break;
    case MDCM_ENCIPHERED:
	/*  |<-------------- data -------------->|
	 *  |<--- offset -->|                    |
	 *  +---------------+--------------------+-----+---------+
	 *  | CMD + HEADERS | DATA TO BE SECURED | CRC | PADDING |
	 *  +---------------+--------------------+-----+---------+ ----------------
	 *  |               |<~~~~v~~~~~~~~~~~~~>|  ^  |         |   (DES / 3DES)
	 *  |               |     `---- crc16() ----'  |         |
	 *  |               |                    |  ^  |         | ----- *or* -----
	 *  |<~~~~~~~~~~~~~~~~~~~~v~~~~~~~~~~~~~>|  ^  |         |  (3K3DES / AES)
	 *                  |     `---- crc32() ----'  |         |
	 *                  |                                    | ---- *then* ----
	 *                  |<---------------------------------->|
	 *                            encypher()/decypher()
	 */

	    if (!(communication_settings & ENC_COMMAND))
		break;
	    edl = enciphered_data_length (tag, *nbytes - offset, communication_settings) + offset;
	    if (!(res = assert_crypto_buffer_size (tag, edl)))
		abort();

	    // Fill in the crypto buffer with data ...
	    memcpy (res, data, *nbytes);
	    if (!(communication_settings & NO_CRC)) {
		// ... CRC ...
		switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
		case AS_LEGACY:
		    iso14443a_crc_append (res + offset, *nbytes - offset);
		    *nbytes += 2;
		    break;
		case AS_NEW:
		    desfire_crc32_append (res, *nbytes);
		    *nbytes += 4;
		    break;
		}
	    }
	    // ... and padding
	    memset (res + *nbytes, 0, edl - *nbytes);

	    *nbytes = edl;

	    mifare_cypher_blocks_chained (tag, NULL, NULL, res + offset, *nbytes - offset, MCD_SEND, (AS_NEW == MIFARE_DESFIRE (tag)->authentication_scheme) ? MCO_ENCYPHER : MCO_DECYPHER);
	break;
    default:
	warnx ("Unknown communication settings");
#ifdef WITH_DEBUG
	abort ();
#endif
	*nbytes = -1;
	res = NULL;
	break;
    }

    return res;
}

void *
mifare_cryto_postprocess_data (FreefareTag tag, void *data, ssize_t *nbytes, int communication_settings)
{
    void *res = data;
    size_t edl;
    void *edata = NULL;
    uint8_t first_cmac_byte;

    MifareDESFireKey key = MIFARE_DESFIRE (tag)->session_key;

    if (!key)
	return data;

    // Return directly if we just have a status code.
    if (1 == *nbytes)
	return res;

    switch (communication_settings & MDCM_MASK) {
    case MDCM_PLAIN:

	if (AS_LEGACY == MIFARE_DESFIRE (tag)->authentication_scheme)
	    break;

	/* pass through */
    case MDCM_MACED:
	switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	case AS_LEGACY:
	    if (communication_settings & MAC_VERIFY) {
		*nbytes -= key_macing_length (key);
		if (*nbytes <= 0) {
		    *nbytes = -1;
		    res = NULL;
#ifdef WITH_DEBUG
		    warnx ("No room for MAC!");
		    abort ();
#endif
		    break;
		}

		edl = enciphered_data_length (tag, *nbytes - 1, communication_settings);
		if (!(edata = malloc (edl)))
		    abort ();

		memcpy (edata, data, *nbytes - 1);
		memset ((uint8_t *)edata + *nbytes - 1, 0, edl - *nbytes + 1);

		mifare_cypher_blocks_chained (tag, NULL, NULL, edata, edl, MCD_SEND, MCO_ENCYPHER);

		if (0 != memcmp ((uint8_t *)data + *nbytes - 1, (uint8_t *)edata + edl - 8, 4)) {
#ifdef WITH_DEBUG
		    warnx ("MACing not verified");
		    hexdump ((uint8_t *)data + *nbytes - 1, key_macing_length (key), "Expect ", 0);
		    hexdump ((uint8_t *)edata + edl - 8, key_macing_length (key), "Actual ", 0);
#endif
		    MIFARE_DESFIRE (tag)->last_pcd_error = CRYPTO_ERROR;
		    *nbytes = -1;
		    res = NULL;
		}
	    }
	    break;
	case AS_NEW:
	    if (!(communication_settings & CMAC_COMMAND))
		break;
	    if (communication_settings & CMAC_VERIFY) {
		if (*nbytes < 9) {
		    *nbytes = -1;
		    res = NULL;
#ifdef WITH_DEBUG
		    warnx ("No room for CMAC!");
		    abort ();
#endif
		    break;
		}
		first_cmac_byte = ((uint8_t *)data)[*nbytes - 9];
		((uint8_t *)data)[*nbytes - 9] = ((uint8_t *)data)[*nbytes-1];
	    }

	    int n = (communication_settings & CMAC_VERIFY) ? 8 : 0;
	    cmac (key, MIFARE_DESFIRE (tag)->ivect, ((uint8_t *)data), *nbytes - n, MIFARE_DESFIRE (tag)->cmac);

	    if (communication_settings & CMAC_VERIFY) {
		((uint8_t *)data)[*nbytes - 9] = first_cmac_byte;
		if (0 != memcmp (MIFARE_DESFIRE (tag)->cmac, (uint8_t *)data + *nbytes - 9, 8)) {
#ifdef WITH_DEBUG
		    warnx ("CMAC NOT verified :-(");
		    hexdump ((uint8_t *)data + *nbytes - 9, 8, "Expect ", 0);
		    hexdump (MIFARE_DESFIRE (tag)->cmac, 8, "Actual ", 0);
#endif
		    MIFARE_DESFIRE (tag)->last_pcd_error = CRYPTO_ERROR;
		    *nbytes = -1;
		    res = NULL;
		} else {
		    *nbytes -= 8;
		}
	    }
	    break;
	}

	free (edata);

	break;
    case MDCM_ENCIPHERED:
	(*nbytes)--;
	bool verified = false;
	int crc_pos;
	int end_crc_pos;
	uint8_t x;

	/*
	 * AS_LEGACY:
	 * ,-----------------+-------------------------------+--------+
	 * \     BLOCK n-1   |              BLOCK n          | STATUS |
	 * /  PAYLOAD | CRC0 | CRC1 | 0x80? | 0x000000000000 | 0x9100 |
	 * `-----------------+-------------------------------+--------+
	 *
	 *         <------------ DATA ------------>
	 * FRAME = PAYLOAD + CRC(PAYLOAD) + PADDING
	 *
	 * AS_NEW:
	 * ,-------------------------------+-----------------------------------------------+--------+
	 * \                 BLOCK n-1     |                  BLOCK n                      | STATUS |
	 * /  PAYLOAD | CRC0 | CRC1 | CRC2 | CRC3 | 0x80? | 0x0000000000000000000000000000 | 0x9100 |
	 * `-------------------------------+-----------------------------------------------+--------+
	 * <----------------------------------- DATA ------------------------------------->|
	 *
	 *         <----------------- DATA ---------------->
	 * FRAME = PAYLOAD + CRC(PAYLOAD + STATUS) + PADDING + STATUS
	 *                                    `------------------'
	 */

	mifare_cypher_blocks_chained (tag, NULL, NULL, res, *nbytes, MCD_RECEIVE, MCO_DECYPHER);

	/*
	 * Look for the CRC and ensure it is followed by NULL padding.  We
	 * can't start by the end because the CRC is supposed to be 0 when
	 * verified, and accumulating 0's in it should not change it.
	 */
	switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	case AS_LEGACY:
	    crc_pos = *nbytes - 8 - 1; // The CRC can be over two blocks
	    if (crc_pos < 0) {
		/* Single block */
		crc_pos = 0;
	    }
	    break;
	case AS_NEW:
	    /* Move status between payload and CRC */
	    res = assert_crypto_buffer_size (tag, (*nbytes) + 1);
	    memcpy (res, data, *nbytes);

	    crc_pos = (*nbytes) - 16 - 3;
	    if (crc_pos < 0) {
		/* Single block */
		crc_pos = 0;
	    }
	    memmove ((uint8_t *)res + crc_pos + 1, (uint8_t *)res + crc_pos, *nbytes - crc_pos);
	    ((uint8_t *)res)[crc_pos] = 0x00;
	    crc_pos++;
	    *nbytes += 1;
	    break;
	}

	do {
	    uint16_t crc16;
	    uint32_t crc;
	    switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	    case AS_LEGACY:
		end_crc_pos = crc_pos + 2;
		iso14443a_crc (res, end_crc_pos, (uint8_t *)&crc16);
		crc = crc16;
		break;
	    case AS_NEW:
		end_crc_pos = crc_pos + 4;
		desfire_crc32 (res, end_crc_pos, (uint8_t *)&crc);
		break;
	    }
	    if (!crc) {
		verified = true;
		for (int n = end_crc_pos; n < *nbytes - 1; n++) {
		    uint8_t byte = ((uint8_t *)res)[n];
		    if (!( (0x00 == byte) || ((0x80 == byte) && (n == end_crc_pos)) ))
			verified = false;
		}
	    }
	    if (verified) {
		*nbytes = crc_pos;
		switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
		case AS_LEGACY:
		    ((uint8_t *)data)[(*nbytes)++] = 0x00;
		    break;
		case AS_NEW:
		    /* The status byte was already before the CRC */
		    break;
		}
	    } else {
		switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
		case AS_LEGACY:
		    break;
		case AS_NEW:
		    x = ((uint8_t *)res)[crc_pos - 1];
		    ((uint8_t *)res)[crc_pos - 1] = ((uint8_t *)res)[crc_pos];
		    ((uint8_t *)res)[crc_pos] = x;
		    break;
		}
		crc_pos++;
	    }
	} while (!verified && (end_crc_pos < *nbytes));

	if (!verified) {
#ifdef WITH_DEBUG
	    /* FIXME In some configurations, the file is transmitted PLAIN */
	    warnx ("CRC not verified in decyphered stream");
#endif
	    MIFARE_DESFIRE (tag)->last_pcd_error = CRYPTO_ERROR;
	    *nbytes = -1;
	    res = NULL;
	}

	break;
    default:
	warnx ("Unknown communication settings");
#ifdef WITH_DEBUG
	abort ();
#endif
	*nbytes = -1;
	res = NULL;
	break;

    }
    return res;
}

void
mifare_cypher_single_block (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareCryptoDirection direction, MifareCryptoOperation operation, size_t block_size)
{
    AES_KEY k;
    uint8_t ovect[MAX_CRYPTO_BLOCK_SIZE];

    if (direction == MCD_SEND) {
	xor (ivect, data, block_size);
    } else {
	memcpy (ovect, data, block_size);
    }

    uint8_t edata[MAX_CRYPTO_BLOCK_SIZE];

    switch (key->type) {
    case T_DES:
	switch (operation) {
	case MCO_ENCYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    break;
	case MCO_DECYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    break;
	}
	break;
    case T_3DES:
	switch (operation) {
	case MCO_ENCYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    break;
	case MCO_DECYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    break;
	}
	break;
    case T_3K3DES:
	switch (operation) {
	case MCO_ENCYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_ENCRYPT);
	    break;
	case MCO_DECYPHER:
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks3), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    break;
	}
	break;
    case T_AES:
	switch (operation) {
	case MCO_ENCYPHER:
	    AES_set_encrypt_key (key->data, 8*16, &k);
	    AES_encrypt (data, edata, &k);
	    break;
	case MCO_DECYPHER:
	    AES_set_decrypt_key (key->data, 8*16, &k);
	    AES_decrypt (data, edata, &k);
	    break;
	}
	break;
    }

    memcpy (data, edata, block_size);

    if (direction == MCD_SEND) {
	memcpy (ivect, data, block_size);
    } else {
	xor (ivect, data, block_size);
	memcpy (ivect, ovect, block_size);
    }
}

/*
 * This function performs all CBC cyphering / deciphering.
 *
 * The tag argument may be NULL, in which case both key and ivect shall be set.
 * When using the tag session_key and ivect for processing data, these
 * arguments should be set to NULL.
 *
 * Because the tag may contain additional data, one may need to call this
 * function with tag, key and ivect defined.
 */
void
mifare_cypher_blocks_chained (FreefareTag tag, MifareDESFireKey key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareCryptoDirection direction, MifareCryptoOperation operation)
{
    size_t block_size;

    if (tag) {
	if (!key)
	    key = MIFARE_DESFIRE (tag)->session_key;
	if (!ivect)
	    ivect = MIFARE_DESFIRE (tag)->ivect;

	switch (MIFARE_DESFIRE (tag)->authentication_scheme) {
	case AS_LEGACY:
	    memset (ivect, 0, MAX_CRYPTO_BLOCK_SIZE);
	    break;
	case AS_NEW:
	    break;
	}
    }

    if (!key || !ivect)
	abort();

    block_size = key_block_size (key);

    size_t offset = 0;
    while (offset < data_size) {
	mifare_cypher_single_block (key, data + offset, ivect, direction, operation, block_size);
	offset += block_size;
    }
}
