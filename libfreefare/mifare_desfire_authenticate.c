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

#include "config.h"

#include <openssl/des.h>

#include <string.h>
#include <strings.h>

#include <freefare.h>
#include "freefare_internal.h"

static void	 xor8 (uint8_t *ivect, uint8_t *data);
static void	 mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac);

static size_t	 padded_data_length (size_t nbytes);
static size_t	 maced_data_length (size_t nbytes);
static size_t	 enciphered_data_length (size_t nbytes);

static void
xor8 (uint8_t *ivect, uint8_t *data)
{
    for (int i = 0; i < 8; i++) {
	data[i] ^= ivect[i];
    }
}

void
rol8(uint8_t *data)
{
    uint8_t first = data[0];
    for (int i = 0; i < 7; i++) {
	data[i] = data[i+1];
    }
    data[7] = first;
}

/*
 * Size required to store nbytes of data in a buffer of size n*8.
 */
static size_t
padded_data_length (size_t nbytes)
{
    if (nbytes % 8)
	return ((nbytes / 8) + 1) * 8;
    else
	return nbytes;
}

/*
 * Buffer size required to MAC nbytes of data
 */
static size_t
maced_data_length (size_t nbytes)
{
    return nbytes + 4;
}
/*
 * Buffer size required to encipher nbytes of data and a two bytes CRC.
 */
static size_t
enciphered_data_length (size_t nbytes)
{
    return padded_data_length (nbytes + 2);
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
mifare_cryto_preprocess_data (MifareTag tag, void *data, size_t *nbytes, int communication_settings)
{
    void *res;
    uint8_t mac[4];
    size_t edl, mdl;

    switch (communication_settings) {
	case 0:
	case 2:
	    res = data;
	    break;
	case 1:
	    edl = padded_data_length (*nbytes);
	    if (!(res = assert_crypto_buffer_size (tag, edl)))
		abort();

	    // Fill in the crypto buffer with data ...
	    memcpy (res, data, *nbytes);
	    // ... and 0 padding
	    bzero ((uint8_t *)res + *nbytes, edl - *nbytes);

	    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, res, edl, MD_SEND, 1);

	    memcpy (mac, (uint8_t *)res + edl - 8, 4);

	    mdl = maced_data_length (*nbytes);
	    if (!(res = assert_crypto_buffer_size (tag, mdl)))
		abort();

	    memcpy (res, data, *nbytes);
	    memcpy ((uint8_t *)res + *nbytes, mac, 4);

	    *nbytes += 4;

	    break;
	case 3:
	    edl = enciphered_data_length (*nbytes);
	    if (!(res = assert_crypto_buffer_size (tag, edl)))
		abort();

	    // Fill in the crypto buffer with data ...
	    memcpy (res, data, *nbytes);
	    // ... CRC ...
	    append_iso14443a_crc (res, *nbytes);
	    // ... and 0 padding
	    bzero ((uint8_t *)(res) + *nbytes + 2, edl - *nbytes - 2);

	    *nbytes = edl;

	    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, res, *nbytes, MD_SEND, 0);

	    break;
	default:
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
    void *edata;

    switch (communication_settings) {
	case 0:
	case 2:
	    break;
	case 1:
	    *nbytes -= 4;

	    edl = enciphered_data_length (*nbytes);
	    edata = malloc (edl);

	    memcpy (edata, data, *nbytes);
	    bzero ((uint8_t *)edata + *nbytes, edl - *nbytes);

	    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, edata, edl, MD_SEND, 1);
	    /*                                                            ,^^^^^^^
	     * No!  This is not a typo! ---------------------------------'
	     */

	    if (0 != memcmp ((uint8_t *)data + *nbytes, (uint8_t *)edata + edl - 8, 4)) {
		printf ("MACing not verified\n");
		*nbytes = -1;
		res = NULL;
	    }

	    free (edata);

	    break;
	case 3:
	    mifare_cbc_des (MIFARE_DESFIRE (tag)->session_key, res, *nbytes, MD_RECEIVE, 0);

	    /*
	     * Look for the CRC and ensure it is following by NULL padding.  We
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
		    for (int n = end_crc_pos; n < *nbytes; n++) {
			uint8_t byte = ((uint8_t *)res)[n];
			if (!( (0x00 == byte) || ((0x80 == byte) && (n == end_crc_pos)) ))
			    verified = false;
		    }
		}
		if (verified) {
		    *nbytes = end_crc_pos - 2;
		} else {
		    end_crc_pos++;
		}
	    } while (!verified && (end_crc_pos < *nbytes));

	    if (!verified) {
		printf ("(3)DES not verified\n");
		*nbytes = -1;
		res = NULL;
	    }

	    break;
	default:
	    printf ("Unknown communication settings\n");
	    *nbytes = -1;
	    res = NULL;
	    break;

    }
    return res;
}

static void
mifare_des (MifareDESFireKey key, uint8_t *data, uint8_t *ivect, MifareDirection direction, int mac)
{
    uint8_t ovect[8];

    if (direction == MD_SEND) {
	xor8 (ivect, data);
    } else {
	memcpy (ovect, data, 8);
    }
    uint8_t edata[8];

    switch (key->type) {
	case T_DES:
	    if (mac) {
		DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_ENCRYPT);
	    } else {
	    DES_ecb_encrypt ((DES_cblock *) data, (DES_cblock *) edata, &(key->ks1), DES_DECRYPT);
	    }
	    memcpy (data, edata, 8);
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
	    memcpy (data, edata, 8);
	    break;
    }

    if (direction == MD_SEND) {
	memcpy (ivect, data, 8);
    } else {
	xor8 (ivect, data);
	memcpy (ivect, ovect, 8);
    }
}

void
mifare_cbc_des (MifareDESFireKey key, uint8_t *data, size_t data_size, MifareDirection direction, int mac)
{
    size_t offset = 0;
    uint8_t ivect[8];
    bzero (ivect, sizeof (ivect));

    while (offset < data_size) {
	mifare_des (key, data + offset, ivect, direction, mac);
	offset += 8;
    }

}
