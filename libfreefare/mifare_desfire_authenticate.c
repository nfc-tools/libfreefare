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
static void	 mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac, size_t block_size);
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
    uint8_t R = (kbs == 8) ? 0x1B : 0x87;

    uint8_t l[kbs];
    bzero (l, kbs);

    uint8_t ivect[kbs];
    bzero (ivect, kbs);

    mifare_cbc_des (key, ivect, l, kbs, MD_RECEIVE, 1);

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

    mifare_cbc_des (key, ivect, buffer, len, MD_SEND, 1);

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
enciphered_data_length (const MifareDESFireKey key, const size_t nbytes, int communication_settings)
{
    size_t crc_length = 0;
    if (!(communication_settings & NO_CRC)) {
    switch (key->type) {
    case T_DES:
    case T_3DES:
	crc_length = 2;
	break;
    case T_AES:
	crc_length = 4;
	break;
    }
    }

    size_t block_size = key_block_size (key);

    return padded_data_length (nbytes + crc_length, block_size);
}


/*
 * Ensure that tag's crypto buffer is large enough to store nbytes of data.
 */
void *
assert_crypto_buffer_size (MifareTag tag, size_t nbytes)
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
mifare_cryto_preprocess_data (MifareTag tag, void *data, size_t *nbytes, off_t offset, int communication_settings)
{
    void *res = data;
    uint8_t mac[4];
    size_t edl, mdl;
    bool append_mac = true;
    MifareDESFireKey key = MIFARE_DESFIRE (tag)->session_key;

    if (!key)
	return data;

    switch (communication_settings & MDCM_MASK) {
    case MDCM_PLAIN:
	if ((T_DES == key->type) || (T_3DES == key->type))
	    break;

	/*
	 * When using new authentication methods, PLAIN data transmission from
	 * the PICC to the PCD are CMACed, so we have to maintain the
	 * cruptographic initialisation vector up-to-date to chaeck data
	 * integrity later.
	 *
	 * The only difference with CMACed data transmission is that the CMAC
	 * is not addpended to the data send byt the PCD to the PICC.
	 */

	append_mac = false;

	/* pass through */
    case MDCM_MACED:
	switch (key->type) {
	case T_DES:
	case T_3DES:
	    if (!(communication_settings & MAC_COMMAND))
		break;
	edl = padded_data_length (*nbytes - offset, key_block_size (MIFARE_DESFIRE (tag)->session_key)) + offset;
	if (!(res = assert_crypto_buffer_size (tag, edl)))
	    abort();

	// Fill in the crypto buffer with data ...
	memcpy (res, data, *nbytes);
	// ... and 0 padding
        memset ((uint8_t *)res + *nbytes, 0, edl - *nbytes);

	mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, (uint8_t *) res + offset, edl - offset, MD_SEND, 1);

	memcpy (mac, (uint8_t *)res + edl - 8, 4);

	// Copy again provided data (was overwritten by mifare_cbc_des)
	memcpy (res, data, *nbytes);

	// Append MAC
	mdl = maced_data_length (MIFARE_DESFIRE (tag)->session_key, *nbytes - offset) + offset;
	if (!(res = assert_crypto_buffer_size (tag, mdl)))
	    abort();

	memcpy ((uint8_t *)res + *nbytes, mac, 4);

	*nbytes += 4;
	    break;
	case T_AES:
	    if (!(communication_settings & CMAC_COMMAND))
		break;
	    cmac (key, MIFARE_DESFIRE (tag)->ivect, res, *nbytes, MIFARE_DESFIRE (tag)->cmac);
	    
	    if (append_mac) {
		mdl = maced_data_length (key, *nbytes);
		if (!(res = assert_crypto_buffer_size (tag, mdl)))
		    abort();

		memcpy (res, data, *nbytes);
		memcpy ((uint8_t *) res + *nbytes, MIFARE_DESFIRE (tag)->cmac, CMAC_LENGTH);
		*nbytes += CMAC_LENGTH;
	    }
	    break;
	}

	break;
    case MDCM_ENCIPHERED:
	/*  |<-------------- data -------------->|
	 *  |<--- offset -->|                    |
	 *  +-----+---------+--------------------+-----+---------+
	 *  | CMD + HEADERS | DATA TO BE SECURED | CRC | PADDING |
	 *  +-----+---------+--------------------+-----+---------+ ----------------
	 *  |               |<~~~~v~~~~~~~~~~~~~>|  ^  |         |   (DES / 3DES)
	 *  |               |     `---- crc16() ----'  |         |
	 *  |               |                    |  ^  |         | ----- *or* -----
	 *  |<~~~~~~~~~~~~~~~~~~~~v~~~~~~~~~~~~~>|  ^  |         |  (3K3DES / AES)
	 *                  |     `---- crc32() ----'  |         |
	 *                  |                                    | ---- *then* ----
	 *                  |<---------------------------------->|
	 *                            encypher()/decypher()
	 */

	switch (key->type) {
	case T_DES:
	case T_3DES:
	    if (!(communication_settings & ENC_COMMAND))
		break;
	edl = enciphered_data_length (MIFARE_DESFIRE (tag)->session_key, *nbytes - offset, communication_settings) + offset;
	if (!(res = assert_crypto_buffer_size (tag, edl)))
	    abort();

	// Fill in the crypto buffer with data ...
	memcpy (res, data, *nbytes);
	if (!(communication_settings & NO_CRC)) {
	// ... CRC ...
	iso14443a_crc_append ((uint8_t *)res + offset, *nbytes - offset);
	} else {
	    bzero ((uint8_t *) res + *nbytes, 2);
	}
	// ... and 0 padding
        memset ((uint8_t *)(res) + *nbytes + 2, 0, edl - *nbytes - 2);

	*nbytes = edl;

	mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, (uint8_t *) res + offset, *nbytes - offset, MD_SEND, 0);

	    break;
	case T_AES:
	edl = enciphered_data_length (MIFARE_DESFIRE (tag)->session_key, *nbytes - offset, communication_settings) + offset;
	if (!(res = assert_crypto_buffer_size (tag, edl)))
	    abort();

	// Fill in the crypto buffer with data ...
	memcpy (res, data, *nbytes);
	size_t pdl;
	if (!(communication_settings & NO_CRC)) {
	    desfire_crc32_append (res, *nbytes);
	    pdl = padded_data_length (*nbytes - offset + 4, key_block_size (MIFARE_DESFIRE (tag)->session_key));
	    bzero ((uint8_t *)res + *nbytes + 4, (offset + pdl) - (*nbytes + 4));
	} else {
	    pdl = padded_data_length (*nbytes - offset, key_block_size (MIFARE_DESFIRE (tag)->session_key));
	    bzero ((uint8_t *)res + *nbytes, (offset + pdl) - (*nbytes));
	}
	    mifare_cbc_des (key, MIFARE_DESFIRE (tag)->ivect, (uint8_t *)res + offset, pdl, MD_SEND, 1);
	    *nbytes = offset + pdl;

	    break;
	}

	break;
    default:
	warnx ("Unknown communication settings");
#if WITH_DEBUG
	abort ();
#endif
	*nbytes = -1;
	res = NULL;
	break;
    }

    return res;
}

void *
mifare_cryto_postprocess_data (MifareTag tag, void *data, ssize_t *nbytes, int communication_settings)
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

	if ((T_DES == key->type) || (T_3DES == key->type))
	    break;

	/* pass through */
    case MDCM_MACED:
	switch (key->type) {
	case T_DES:
	case T_3DES:
	    if (communication_settings & MAC_VERIFY) {
	*nbytes -= key_macing_length (key);

	edl = enciphered_data_length (MIFARE_DESFIRE (tag)->session_key, *nbytes - 1, communication_settings);
	edata = malloc (edl);

	memcpy (edata, data, *nbytes - 1);
	memset ((uint8_t *)edata + *nbytes - 1, 0, edl - *nbytes + 1);

	mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, edata, edl, MD_SEND, 1);
	/*                                                                                         ,^^^^^^^
	 * No!  This is not a typo! --------------------------------------------------------------'
	 */

	if (0 != memcmp ((uint8_t *)data + *nbytes - 1, (uint8_t *)edata + edl - 8, 4)) {
	    warnx ("MACing not verified");
#if WITH_DEBUG
	    hexdump ((uint8_t *)data + *nbytes - 1, 4, "Expect ", 0);
	    hexdump ((uint8_t *)edata + edl - 8, 4, "Actual ", 0);
	    abort ();
#endif
	    *nbytes = -1;
	    res = NULL;
	}
	    }
	    break;
	case T_AES:
	    if (!(communication_settings & CMAC_COMMAND))
		break;
	    if (communication_settings & CMAC_VERIFY) {
		if (*nbytes < 9) {
		    // XXX: Can't we avoid abort() -ing?
		    warnx ("No room for CMAC!");
		    abort ();
		}
		first_cmac_byte = ((uint8_t *)data)[*nbytes - 9];
		((uint8_t *)data)[*nbytes - 9] = ((uint8_t *)data)[*nbytes-1];
	    }

	    int n = (communication_settings & CMAC_VERIFY) ? 8 : 0;
	    cmac (key, MIFARE_DESFIRE (tag)->ivect, ((uint8_t *)data), *nbytes - n, MIFARE_DESFIRE (tag)->cmac);

	    if (communication_settings & CMAC_VERIFY) {
		((uint8_t *)data)[*nbytes - 9] = first_cmac_byte;
		if (0 != memcmp (MIFARE_DESFIRE (tag)->cmac, (uint8_t *)data + *nbytes - 9, 8)) {
#if WITH_DEBUG
		    warnx ("CMAC NOT verified :-(");
		    hexdump ((uint8_t *)data + *nbytes - 9, 8, "Expect ", 0);
		    hexdump (MIFARE_DESFIRE (tag)->cmac, 8, "Actual ", 0);
		    abort ();
#endif
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
	switch (key->type) {
	case T_DES:
	case T_3DES:
	mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, res, *nbytes, MD_RECEIVE, 0);

	/*
	 * Look for the CRC and ensure it is followed by NULL padding.  We
	 * can't start by the end because the CRC is supposed to be 0 when
	 * verified, and accumulating 0's in it should not change it.
	 */
	bool verified = false;
	int end_crc_pos = *nbytes - 7; // The CRC can be over two blocks

	do {
	    uint16_t crc;
	    iso14443a_crc (res, end_crc_pos, (uint8_t *)&crc);
	    if (!crc) {
		verified = true;
		for (int n = end_crc_pos; n < *nbytes - 1; n++) {
		    uint8_t byte = ((uint8_t *)res)[n];
		    if (!( (0x00 == byte) || ((0x80 == byte) && (n == end_crc_pos)) ))
			verified = false;
		}
	    }
	    if (verified) {
		*nbytes = end_crc_pos - 2;
		((uint8_t *)data)[(*nbytes)++] = 0x00;
	    } else {
		end_crc_pos++;
	    }
	} while (!verified && (end_crc_pos < *nbytes - 1));

	if (!verified) {
	    warnx ("(3)DES not verified");
#if WITH_DEBUG
	    abort ();
#endif
	    *nbytes = -1;
	    res = NULL;
	}
	break;

	case T_AES:
	    (*nbytes)--;
	    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, MIFARE_DESFIRE (tag)->ivect, res, *nbytes, MD_RECEIVE, 0);
	    uint8_t *p = ((uint8_t *)res) + *nbytes - 1;
	    while (!*p) {
		p--;
	    }
	    if (0x80 == *p)
		p--;
	    p -= 3;

	    uint8_t crc_ref[4];
	    memcpy (crc_ref, p, 4);
	    *p++ = ((uint8_t *)res)[*nbytes];

	    uint8_t crc[4];
	    desfire_crc32 (res, p - (uint8_t *)res, crc);

	    if (memcmp (crc, crc_ref, 4)) {
		warnx ("AES CRC32 not verified in AES stream");
#if WITH_DEBUG
		hexdump (crc_ref, 4, "Expect ", 0);
		hexdump (crc, 4, "Actual ", 0);
		abort ();
#endif
		*nbytes = -1;
		res = NULL;
	    }
	    *nbytes = p - (uint8_t *)res;
	}
	break;
    default:
	warnx ("Unknown communication settings");
#if WITH_DEBUG
	abort ();
#endif
	*nbytes = -1;
	res = NULL;
	break;

    }
    return res;
}

static void
mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac, size_t block_size)
{
    uint8_t ovect[MAX_CRYPTO_BLOCK_SIZE];

    if (direction == MD_SEND) {
	xor (ivect, data, block_size);
    } else {
	memcpy (ovect, data, block_size);
    }

    uint8_t edata[MAX_CRYPTO_BLOCK_SIZE];

    switch (key->type) {
    case T_DES:
	if (mac) {
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	} else {
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	}
	break;
    case T_3DES:
	if (mac) {
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	} else {
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    DES_ecb_encrypt ((DES_cblock *) edata, (DES_cblock *) data,  &(key->ks2), DES_ENCRYPT);
	    DES_ecb_encrypt ((DES_cblock *) data,  (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	}
	break;
    case T_AES:
	if (mac) {
	    AES_KEY k;
	    AES_set_encrypt_key (key->data, 8*16, &k);
	    AES_encrypt (data, edata, &k);
	} else {
	    AES_KEY k;
	    AES_set_decrypt_key (key->data, 8*16, &k);
	    AES_decrypt (data, edata, &k);
	}
	break;
    }

    memcpy (data, edata, block_size);

    if (direction == MD_SEND) {
	memcpy (ivect, data, block_size);
    } else {
	xor (ivect, data, block_size);
	memcpy (ivect, ovect, block_size);
    }
}

void
mifare_cbc_des (MifareDESFireKey key, uint8_t *ivect, uint8_t *data, size_t data_size, MifareDirection direction, int mac)
{
    size_t block_size;

    switch (key->type) {
	case T_DES:
	case T_3DES:
            memset (ivect, 0, MAX_CRYPTO_BLOCK_SIZE);
	    block_size = 8;
	    break;
	case T_AES:
	    block_size = 16;
	    break;
    }

    size_t offset = 0;
    while (offset < data_size) {
	mifare_des (key, data + offset, ivect, direction, mac, block_size);
	offset += block_size;
    }
}
