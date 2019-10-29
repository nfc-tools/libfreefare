#include <stdlib.h>
#include <string.h>

#include <openssl/des.h>

#include <freefare.h>
#include "freefare_internal.h"

static inline void update_key_schedules(MifareDESFireKey key);

static inline void
update_key_schedules(MifareDESFireKey key)
{
    DES_set_key((DES_cblock *)key->data, &(key->ks1));
    DES_set_key((DES_cblock *)(key->data + 8), &(key->ks2));
    if (MIFARE_KEY_3K3DES == key->type) {
	DES_set_key((DES_cblock *)(key->data + 16), &(key->ks3));
    }
}

MifareDESFireKey
mifare_desfire_des_key_new(const uint8_t value[8])
{
    uint8_t data[8];
    memcpy(data, value, 8);
    for (int n = 0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_des_key_new_with_version(data);
}

MifareDESFireKey
mifare_desfire_des_key_new_with_version(const uint8_t value[8])
{
    MifareDESFireKey key;

    if ((key = malloc(sizeof(struct mifare_desfire_key)))) {
	key->type = MIFARE_KEY_DES;
	memcpy(key->data, value, 8);
	memcpy(key->data + 8, value, 8);
	update_key_schedules(key);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_3des_key_new(const uint8_t value[16])
{
    uint8_t data[16];
    memcpy(data, value, 16);
    for (int n = 0; n < 8; n++)
	data[n] &= 0xfe;
    for (int n = 8; n < 16; n++)
	data[n] |= 0x01;
    return mifare_desfire_3des_key_new_with_version(data);
}

MifareDESFireKey
mifare_desfire_3des_key_new_with_version(const uint8_t value[16])
{
    MifareDESFireKey key;

    if ((key = malloc(sizeof(struct mifare_desfire_key)))) {
	key->type = MIFARE_KEY_2K3DES;
	memcpy(key->data, value, 16);
	update_key_schedules(key);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_3k3des_key_new(const uint8_t value[24])
{
    uint8_t data[24];
    memcpy(data, value, 24);
    for (int n = 0; n < 8; n++)
	data[n] &= 0xfe;
    return mifare_desfire_3k3des_key_new_with_version(data);
}

MifareDESFireKey
mifare_desfire_3k3des_key_new_with_version(const uint8_t value[24])
{
    MifareDESFireKey key;

    if ((key = malloc(sizeof(struct mifare_desfire_key)))) {
	key->type = MIFARE_KEY_3K3DES;
	memcpy(key->data, value, 24);
	update_key_schedules(key);
    }
    return key;
}

MifareDESFireKey
mifare_desfire_aes_key_new(const uint8_t value[16])
{
    return mifare_desfire_aes_key_new_with_version(value, 0);
}

MifareDESFireKey
mifare_desfire_aes_key_new_with_version(const uint8_t value[16], uint8_t version)
{
    MifareDESFireKey key;

    if ((key = malloc(sizeof(struct mifare_desfire_key)))) {
	memcpy(key->data, value, 16);
	key->type = MIFARE_KEY_AES128;
	key->aes_version = version;
    }
    return key;
}

uint8_t
mifare_desfire_key_get_version(MifareDESFireKey key)
{
    uint8_t version = 0;

    if (key->type == MIFARE_KEY_AES128)
	return key->aes_version;

    for (int n = 0; n < 8; n++) {
	version |= ((key->data[n] & 1) << (7 - n));
    }

    return version;
}

void
mifare_desfire_key_set_version(MifareDESFireKey key, uint8_t version)
{
    if (key->type == MIFARE_KEY_AES128) {
	key->aes_version = version;
	return;
    }

    for (int n = 0; n < 8; n++) {
	uint8_t version_bit = ((version & (1 << (7 - n))) >> (7 - n));
	key->data[n] &= 0xfe;
	key->data[n] |= version_bit;
	switch (key->type) {
	case MIFARE_KEY_DES:
	    // DESFire cards always treat DES keys as special cases of 2K3DES
	    // keys. The DESFire functional specification explicitly points
	    // out that if the subkeys of a 2K3DES key are exactly identical
	    // (including parity bits), then (and only then) is the key treated
	    // as a DES key for authentication purposes. Specifically, the
	    // version/parity bits must be idential, as well as the rest of the
	    // key, otherwise the PICC will treat it as a 2K3DES key.  This
	    // next line ensure that.
	    key->data[n + 8] = key->data[n];
	    break;
	case MIFARE_KEY_2K3DES:
	    // But what if we really did want the PICC to treat the key as a
	    // real 2K3DES key, even if the actual 56 bits of the subkeys did
	    // match? To ensure that such as case still works (largely because
	    // the datasheet implies authentication would behave differently
	    // otherwise), we need to ensure that the parity bits on the subkeys
	    // explicitly do not match. The easiest way to ensure that is to
	    // always write the bits of `~version` to the parity bits of the
	    // second subkey. Note that this would only have an effect at the
	    // PICC level if the subkeys were otherwise identical.
	    key->data[n + 8] &= 0xfe;
	    key->data[n + 8] |= !version_bit;
	    break;
	default:
	    break;
	}
    }
}

MifareDESFireKey
mifare_desfire_session_key_new(const uint8_t rnda[], const uint8_t rndb[], MifareDESFireKey authentication_key)
{
    MifareDESFireKey key = NULL;

    uint8_t buffer[24];

    switch (authentication_key->type) {
    case MIFARE_KEY_DES:
	memcpy(buffer, rnda, 4);
	memcpy(buffer + 4, rndb, 4);
	key = mifare_desfire_des_key_new_with_version(buffer);
	break;
    case MIFARE_KEY_2K3DES:
	memcpy(buffer, rnda, 4);
	memcpy(buffer + 4, rndb, 4);
	memcpy(buffer + 8, rnda + 4, 4);
	memcpy(buffer + 12, rndb + 4, 4);
	key = mifare_desfire_3des_key_new_with_version(buffer);
	break;
    case MIFARE_KEY_3K3DES:
	memcpy(buffer, rnda, 4);
	memcpy(buffer + 4, rndb, 4);
	memcpy(buffer + 8, rnda + 6, 4);
	memcpy(buffer + 12, rndb + 6, 4);
	memcpy(buffer + 16, rnda + 12, 4);
	memcpy(buffer + 20, rndb + 12, 4);
	key = mifare_desfire_3k3des_key_new(buffer);
	break;
    case MIFARE_KEY_AES128:
	memcpy(buffer, rnda, 4);
	memcpy(buffer + 4, rndb, 4);
	memcpy(buffer + 8, rnda + 12, 4);
	memcpy(buffer + 12, rndb + 12, 4);
	key = mifare_desfire_aes_key_new(buffer);
	break;
    }

    return key;
}

MifareKeyType
mifare_desfire_key_get_type(MifareDESFireKey key)
{
    return key->type;
}

void
mifare_desfire_key_free(MifareDESFireKey key)
{
    free(key);
}
