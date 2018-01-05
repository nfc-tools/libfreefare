#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include <openssl/des.h>

#include <freefare.h>
#include "freefare_internal.h"

#define AN10922_DIV_AES128	0x01
#define AN10922_DIV_AES192_1	0x11
#define AN10922_DIV_AES192_2	0x12
#define AN10922_DIV_2K3DES_1	0x21
#define AN10922_DIV_2K3DES_2	0x22
#define AN10922_DIV_3K3DES_1	0x31
#define AN10922_DIV_3K3DES_2	0x32
#define AN10922_DIV_3K3DES_3	0x33

MifareKeyDeriver
mifare_key_deriver_new_an10922(MifareDESFireKey master_key, MifareKeyType output_key_type)
{
    MifareKeyDeriver deriver = NULL;
    const int master_key_block_size = key_block_size(master_key);

    switch(output_key_type) {
    case MIFARE_KEY_AES128:
	if (master_key_block_size != 16) {
	    errno = EINVAL;
	    return NULL;
	}
	break;

    case MIFARE_KEY_2K3DES:
	if ((master_key_block_size != 8) && (master_key_block_size != 16)) {
	    errno = EINVAL;
	    return NULL;
	}
	break;

    case MIFARE_KEY_3K3DES:
	if (master_key_block_size != 8) {
	    errno = EINVAL;
	    return NULL;
	}
	break;

    case MIFARE_KEY_DES:
    // AN10922 doesn't define a DIV constant for
    // deriving plain 56-bit DES keys.
    default:
	// Unsupported output key type.
	errno = EINVAL;
	return NULL;
    }

    if ((deriver = malloc(sizeof(struct mifare_key_deriver)))) {
	deriver->master_key = master_key;
	deriver->output_key_type = output_key_type;
	cmac_generate_subkeys(deriver->master_key);
    }

    return deriver;
}

void
mifare_key_deriver_free(MifareKeyDeriver deriver)
{
    memset(deriver, 0, sizeof(*deriver));
    free(deriver);
}

int
mifare_key_deriver_begin(MifareKeyDeriver deriver)
{
    memset(deriver->m, 0, sizeof(deriver->m));

    // We skip byte zero for the DIV constant, which
    // we will fill out in the call to end(). We also
    // use len==0 as an overflow error condition.
    deriver->len = 1;

    return 0;
}

int
mifare_key_deriver_update_data(MifareKeyDeriver deriver, const uint8_t *data, size_t len)
{
    if (deriver->len == 0) {
	// Overflow from previous update call.
	errno = EOVERFLOW;
	return -1;
    }

    if (len > sizeof(deriver->m) - deriver->len) {
	deriver->len = 0; // Remember that we have an error.
	errno = EOVERFLOW;
	return -1;
    }

    memcpy(deriver->m + deriver->len, data, len);
    deriver->len += (int)len;

    return 0;
}

int
mifare_key_deriver_update_cstr(MifareKeyDeriver deriver, const char *cstr)
{
    return mifare_key_deriver_update_data(deriver, (const uint8_t*)cstr, strlen(cstr));
}

int
mifare_key_deriver_update_aid(MifareKeyDeriver deriver, MifareDESFireAID aid)
{
    return mifare_key_deriver_update_data(deriver, aid->data, sizeof(aid->data));
}

int
mifare_key_deriver_update_uid(MifareKeyDeriver deriver, FreefareTag tag)
{
    int ret = 0;
    const uint8_t* uid_data = NULL;
    uint8_t desfire_uid[7];
    uint8_t uid_len = 0;

    switch (tag->info.nm.nmt) {
    case NMT_FELICA:
	uid_data = tag->info.nti.nfi.abtId;
	uid_len = 8;
	break;
    case NMT_ISO14443A:
	uid_data = tag->info.nti.nai.abtUid;
	uid_len = tag->info.nti.nai.szUidLen;
	break;
    case NMT_DEP:
    case NMT_ISO14443B2CT:
    case NMT_ISO14443B2SR:
    case NMT_ISO14443B:
    case NMT_ISO14443BI:
    case NMT_JEWEL:
    case NMT_BARCODE:
	ret = -1;
	errno = EINVAL;
	break;
    }

    if ((uid_len == 4) && (freefare_get_tag_type(tag) == MIFARE_DESFIRE)) {
	// DESFire card is using random UID. We need
	// to explicitly get the real static UID.

	if (mifare_desfire_get_card_uid_raw(tag, desfire_uid) < 0) {
	    ret = -1;
	} else {
	    uid_data = desfire_uid;
	}
    }

    if (ret >= 0) {
	ret = mifare_key_deriver_update_data(deriver, uid_data, uid_len);
    }

    return ret;
}

static void
deriver_cmac(MifareKeyDeriver deriver, uint8_t* output)
{
    uint8_t ivect[24];
    memset(ivect, 0, sizeof(ivect));
    cmac(deriver->master_key, ivect, deriver->m, deriver->len, output);
}

static uint8_t
get_key_type_data_len(MifareKeyType type)
{
    switch(type) {
    case MIFARE_KEY_AES128:
    case MIFARE_KEY_2K3DES:
	return 16;

    case MIFARE_KEY_DES:
	return 8;

    case MIFARE_KEY_3K3DES:
	return 24;
    }

    // This should never happen.
    return 0;
}

static uint8_t
get_key_data_len(MifareDESFireKey key)
{
    return get_key_type_data_len(key->type);
}

int
mifare_key_deriver_end_raw(MifareKeyDeriver deriver, uint8_t* diversified_bytes, size_t max_len)
{
    const uint8_t len = get_key_type_data_len(deriver->output_key_type);
    const int master_key_block_size = key_block_size(deriver->master_key);
    uint8_t data[24];

    if (deriver->len == 0) {
	// Overflow from previous update call.
	// We must not emit a key if there was a previous error,
	// otherwise bugs may go unnoticed.
	errno = EOVERFLOW;
	return -1;
    }

    if (len == 0) {
	errno = EINVAL;
	return -1;
    }

    if (max_len > len) {
	max_len = len;
    }

    memset(data, 0, sizeof(data));

    if ((master_key_block_size == 16) && (deriver->output_key_type == MIFARE_KEY_AES128)) {
	deriver->m[0] = AN10922_DIV_AES128;
	deriver_cmac(deriver, data);

    } else if ((master_key_block_size == 16) && (deriver->output_key_type == MIFARE_KEY_2K3DES)) {
	// This technically isn't defined in AN10922, but it is
	// straightforward adaptation that is useful for diversifying
	// MIFARE Ultralight C keys.
	deriver->m[0] = AN10922_DIV_2K3DES_1;
	deriver_cmac(deriver, data);

    } else if ((master_key_block_size == 8) && (deriver->output_key_type == MIFARE_KEY_2K3DES)) {
	deriver->m[0] = AN10922_DIV_2K3DES_1;
	deriver_cmac(deriver, data + 0);
	deriver->m[0] = AN10922_DIV_2K3DES_2;
	deriver_cmac(deriver, data + 8);

    } else if ((master_key_block_size == 8) && (deriver->output_key_type == MIFARE_KEY_3K3DES)) {
	deriver->m[0] = AN10922_DIV_3K3DES_1;
	deriver_cmac(deriver, data + 0);
	deriver->m[0] = AN10922_DIV_3K3DES_2;
	deriver_cmac(deriver, data + 8);
	deriver->m[0] = AN10922_DIV_3K3DES_3;
	deriver_cmac(deriver, data + 16);

    } else {
	// AN10922 doesn't describe how to perform this derivation.
	errno = EINVAL;
	return -1;
    }

    memcpy(diversified_bytes, data, max_len);

    // Wipe key info from stack
    memset(data, 0, sizeof(data));

    return len;
}

MifareDESFireKey
mifare_key_deriver_end(MifareKeyDeriver deriver)
{
    MifareDESFireKey ret = NULL;
    uint8_t data[24];
    int len = mifare_key_deriver_end_raw(deriver, data, sizeof(data));

    if (len <= 0) {
	return NULL;
    }

    switch (deriver->output_key_type) {
    case MIFARE_KEY_AES128:
	ret = mifare_desfire_aes_key_new_with_version(data, 0);
	break;

    case MIFARE_KEY_DES:
	ret = mifare_desfire_des_key_new(data);
	break;

    case MIFARE_KEY_2K3DES:
	ret = mifare_desfire_3des_key_new(data);
	break;

    case MIFARE_KEY_3K3DES:
	ret = mifare_desfire_3k3des_key_new(data);
	break;
    }

    // Update the key version
    if (ret != NULL) {
	mifare_desfire_key_set_version(ret, mifare_desfire_key_get_version(deriver->master_key));
    }

    // Wipe key info from stack
    memset(data, 0, sizeof(data));

    return ret;
}
