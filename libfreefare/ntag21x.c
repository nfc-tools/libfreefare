/*
 * This implementation was written based on information provided by the
 * following documents:
 *
 * Contactless Single-trip Ticket IC
 * MF0 IC U1
 * Functional Specification
 * Revision 3.0
 * March 2003
 *
 * NTAG213/215/216
 * NFC Forum Type 2 Tag compliant IC with 144/504/888 bytes user memory
 * Revision 3.2
 * June 2015
 */

#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#if defined(HAVE_SYS_TYPES_H)
    #include <sys/types.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#ifdef WITH_DEBUG
    #include <libutil.h>
#endif

#include <freefare.h>
#include "freefare_internal.h"

#define NTAG_ASSERT_VALID_PAGE(tag, page, mode_write) \
    do { \
	if (mode_write) { \
	    if (page<=0x02) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_213&&page>0x2C) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_215&&page>0x86) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_216&&page>0xE6) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_UNKNOWN) \
	    {return errno = EINVAL, -1;} \
	} else { \
	    if(NTAG_21x(tag)->subtype == NTAG_213&&page>0x2C) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_215&&page>0x86) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_216&&page>0xE6) \
	    {return errno = EINVAL, -1;} \
	    else if(NTAG_21x(tag)->subtype == NTAG_UNKNOWN) \
	    {return errno = EINVAL, -1;} \
	} \
    } while (0)

#define NTAG_TRANSCEIVE(tag, msg, res) \
    do { \
	errno = 0; \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	int _res; \
	if ((_res = nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, __##res##_size, 0)) < 0) { \
	    return errno = EIO, -1; \
	} \
	__##res##_n = _res; \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
    } while (0)

#define NTAG_TRANSCEIVE_RAW(tag, msg, res) \
    do { \
	errno = 0; \
	if (nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, false) < 0) { \
	    errno = EIO; \
	    return -1; \
	} \
	DEBUG_XFER (msg, __##msg##_n, "===> "); \
	int _res; \
	if ((_res = nfc_initiator_transceive_bytes (tag->device, msg, __##msg##_n, res, __##res##_size, 0)) < 0) { \
	    nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, true); \
	    return errno = EIO, -1; \
	} \
	__##res##_n = _res; \
	DEBUG_XFER (res, __##res##_n, "<=== "); \
	if (nfc_device_set_property_bool (tag->device, NP_EASY_FRAMING, true) < 0) { \
	    errno = EIO; \
	    return -1; \
	} \
    } while (0)


bool
ntag21x_taste(nfc_device *device, nfc_target target)
{
    return target.nm.nmt == NMT_ISO14443A && target.nti.nai.btSak == 0x00 && ntag21x_is_auth_supported(device, target.nti.nai);
}


/*
 * Memory management functions.
 */

/*
 * Allocates and initialize a NTAG tag.
 */
static FreefareTag
_ntag21x_tag_new(nfc_device *device, nfc_target target)
{
    FreefareTag tag;

    if ((tag = malloc(sizeof(struct ntag21x_tag)))) {
	tag->type = NTAG_21x ;
	tag->free_tag = ntag21x_tag_free;
	tag->device = device;
	tag->info = target;
	tag->active = 0;
	NTAG_21x(tag)->subtype = NTAG_UNKNOWN;
	NTAG_21x(tag)->vendor_id = 0x00;
	NTAG_21x(tag)->product_type = 0x00;
	NTAG_21x(tag)->product_subtype = 0x00;
	NTAG_21x(tag)->major_product_version = 0x00;
	NTAG_21x(tag)->minor_product_version = 0x00;
	NTAG_21x(tag)->storage_size = 0x00;
	NTAG_21x(tag)->protocol_type = 0x00;
	NTAG_21x(tag)->last_error = OPERATION_OK;
    }

    return tag;
}

static FreefareTag
_ntag21x_tag_reuse(FreefareTag old_tag)
{
    FreefareTag tag;

    if ((tag = malloc(sizeof(struct ntag21x_tag)))) {
	tag->type = NTAG_21x ;
	tag->free_tag = ntag21x_tag_free;
	tag->device = old_tag->device;
	tag->info = old_tag->info;
	tag->active = 0;
	NTAG_21x(tag)->subtype = NTAG_21x(old_tag)->subtype;
	NTAG_21x(tag)->vendor_id = NTAG_21x(old_tag)->vendor_id;
	NTAG_21x(tag)->product_type = NTAG_21x(old_tag)->product_type;
	NTAG_21x(tag)->product_subtype = NTAG_21x(old_tag)->product_subtype;
	NTAG_21x(tag)->major_product_version = NTAG_21x(old_tag)->major_product_version;
	NTAG_21x(tag)->minor_product_version = NTAG_21x(old_tag)->minor_product_version;
	NTAG_21x(tag)->storage_size = NTAG_21x(old_tag)->storage_size;
	NTAG_21x(tag)->protocol_type = NTAG_21x(old_tag)->protocol_type;
	NTAG_21x(tag)->last_error = NTAG_21x(old_tag)->last_error;
    }

    return tag;
}

FreefareTag
ntag21x_tag_new(nfc_device *device, nfc_target target)
{
    return _ntag21x_tag_new(device, target);
}

FreefareTag
ntag21x_tag_reuse(FreefareTag tag)
{
    return _ntag21x_tag_reuse(tag);
}

/*
 * Create new key for NTAG
 */
NTAG21xKey
ntag21x_key_new(const uint8_t data[4], const uint8_t pack[2])
{
    NTAG21xKey key;
    if ((key = malloc(sizeof(struct ntag21x_key)))) {
	memcpy(key->data, data, 4);
	memcpy(key->pack, pack, 2);
    }
    return key;
}

/*
 * Free NTAG key
 */
void
ntag21x_key_free(NTAG21xKey key)
{
    free(key);
}

/*
 * Free the provided tag.
 */
void
ntag21x_tag_free(FreefareTag tag)
{
    free(tag);
}



/*
 * MIFARE card communication preparation functions
 *
 * The following functions send NFC commands to the initiator to prepare
 * communication with a MIFARE card, and perform required cleanups after using
 * the target.
 */


/*
 * Establish connection to the provided tag.
 */
int
ntag21x_connect(FreefareTag tag)
{
    ASSERT_INACTIVE(tag);

    nfc_target pnti;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    if (nfc_initiator_select_passive_target(tag->device, modulation, tag->info.nti.nai.abtUid, tag->info.nti.nai.szUidLen, &pnti) >= 0) {
	tag->active = 1;

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
ntag21x_disconnect(FreefareTag tag)
{
    ASSERT_ACTIVE(tag);

    if (nfc_initiator_deselect_target(tag->device) >= 0) {
	tag->active = 0;
    } else {
	errno = EIO;
	return -1;
    }
    return 0;
}

/*
 * Gather information about tag
 */
int
ntag21x_get_info(FreefareTag tag)
{
    ASSERT_ACTIVE(tag);

    // Init buffers
    BUFFER_INIT(cmd, 1);
    BUFFER_INIT(res, 8);

    // Append get version command to buffer
    BUFFER_APPEND(cmd, 0x60);

    NTAG_TRANSCEIVE_RAW(tag, cmd, res);  // Send & receive to & from tag

    NTAG_21x(tag)->vendor_id = res[1];
    NTAG_21x(tag)->product_type = res[2];
    NTAG_21x(tag)->product_subtype = res[3];
    NTAG_21x(tag)->major_product_version = res[4];
    NTAG_21x(tag)->minor_product_version = res[5];
    NTAG_21x(tag)->storage_size = res[6];
    NTAG_21x(tag)->protocol_type = res[7];

    // Set ntag subtype based on storage size
    switch (NTAG_21x(tag)->storage_size) {
    case 0x0f:
	NTAG_21x(tag)->subtype = NTAG_213;
	break;
    case 0x11:
	NTAG_21x(tag)->subtype = NTAG_215;
	break;
    case 0x13:
	NTAG_21x(tag)->subtype = NTAG_216;
	break;
    default:
	NTAG_21x(tag)->last_error = UNKNOWN_TAG_TYPE_ERROR;
	return -1;
    }
    return 0;
}

/*
 * Get subtype of tag
 */
enum ntag_tag_subtype
ntag21x_get_subtype(FreefareTag tag) {
    return NTAG_21x(tag)->subtype;
}

/*
 * Get last page
 */
uint8_t
ntag21x_get_last_page(FreefareTag tag)
{
    switch (NTAG_21x(tag)->subtype) {
    case NTAG_213:
	return 0x2C;
    case NTAG_215:
	return 0x86;
    case NTAG_216:
	return 0xE6;
    default:
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return 0x00;
    }
}

/*
 * Read signature
 */
int
ntag21x_read_signature(FreefareTag tag, uint8_t *data)
{
    ASSERT_ACTIVE(tag);

    // Init buffers
    BUFFER_INIT(cmd, 2);
    BUFFER_INIT(res, 32);

    // Append get version command to buffer
    BUFFER_APPEND(cmd, 0x3C);
    BUFFER_APPEND(cmd, 0x00);

    NTAG_TRANSCEIVE_RAW(tag, cmd, res);  // Send & receive to & from tag

    memcpy(data, res, 32); // Copy response to data output
    return 0;
}

/*
 * Card manipulation functions
 *
 * The following functions perform direct communication with the connected
 * NTAG21x tag.
 */

/*
 *  Auth properties manipulation
 */
int
ntag21x_set_pwd(FreefareTag tag, uint8_t data[4]) // Set password
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    uint8_t page = ntag21x_get_last_page(tag) - 1; // PWD page is located 1 before last page
    int res = ntag21x_write(tag, page, data);
    return res;
}

int
ntag21x_set_pack(FreefareTag tag, uint8_t data[2]) // Set pack
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(buff, 4);
    BUFFER_APPEND_BYTES(buff, data, 2);
    BUFFER_APPEND(buff, 0x00);
    BUFFER_APPEND(buff, 0x00);
    uint8_t page = ntag21x_get_last_page(tag); // PACK page is located on last page
    int res = ntag21x_write(tag, page, buff);
    return res;
}

int
ntag21x_set_key(FreefareTag tag, const NTAG21xKey key) // Set key
{
    int res;
    // Set password
    res = ntag21x_set_pwd(tag, key->data);
    if (res < 0)
	return res;

    // Set pack
    res = ntag21x_set_pack(tag, key->pack);
    return res;
}

int
ntag21x_set_auth(FreefareTag tag, uint8_t byte) // Set AUTH0 byte (from which page starts password protection)
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    int page = ntag21x_get_last_page(tag) - 3; // AUTH0 byte is on 4th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    cdata[3] = byte; // Set AUTH0 byte in buffer
    res = ntag21x_write(tag, page, cdata); // Write new configuration to tag
    return res;
}

int
ntag21x_get_auth(FreefareTag tag, uint8_t *byte) // Get AUTH0 byte
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    int page = ntag21x_get_last_page(tag) - 3; // AUTH0 byte is on 4th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    *byte = cdata[3];  // Get AUTH0 byte in buffer
    return res;
}

int
ntag21x_access_enable(FreefareTag tag, uint8_t byte) // Enable access feature in ACCESS byte
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    int page = ntag21x_get_last_page(tag) - 2; // ACCESS byte is on 3th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    cdata[0] |= byte; // Set bit to 1 in ACCESS byte
    res = ntag21x_write(tag, page, cdata); // Write new configuration to tag
    return res;
}

int
ntag21x_access_disable(FreefareTag tag, uint8_t byte) // Disable access feature in ACCESS byte
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    int page = ntag21x_get_last_page(tag) - 2; // ACCESS byte is on 3th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    cdata[0] &= ~byte; // Set bit to 0 in ACCESS byte
    res = ntag21x_write(tag, page, cdata); // Write new configuration to tag
    return res;
}

int
ntag21x_get_access(FreefareTag tag, uint8_t *byte) // Get ACCESS byte
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    uint8_t page = ntag21x_get_last_page(tag) - 2; // ACCESS byte is on 3th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    memcpy(byte, cdata, 1); // Return 1 byte of page
    return res;
}

int
ntag21x_check_access(FreefareTag tag, uint8_t byte, bool *result) // Check if access feature is enabled
{
    BUFFER_INIT(buff, 1);
    int res;
    res = ntag21x_get_access(tag, buff);
    if (res < 0)
	return res; // Return error if can't get access byte

    *result = (buff[0] & byte) > 0; // Set result, check if bit is 1 in access byte

    return res;
}

int
ntag21x_get_authentication_limit(FreefareTag tag, uint8_t *byte) // Get authentication limit
{
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }
    BUFFER_INIT(cdata, 4);
    uint8_t page = ntag21x_get_last_page(tag) - 2; // ACCESS byte is on 3th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    cdata[0] &= 0x07; // Extract last 3 bits from access byte
    memcpy(byte, cdata, 1); // Return 1 byte of page
    return res;
}

int
ntag21x_set_authentication_limit(FreefareTag tag, uint8_t byte) // Set authentication limit (0x00 = disabled, [0x01,0x07] = valid range, > 0x07 invalid range)
{
    if (byte > 7) // Check for invalid range of auth limit
	return -1;
    if (NTAG_21x(tag)->subtype == NTAG_UNKNOWN) {
	NTAG_21x(tag)->last_error = TAG_INFO_MISSING_ERROR;
	return -1;
    }

    BUFFER_INIT(cdata, 4);
    int page = ntag21x_get_last_page(tag) - 2; // ACCESS byte is on 3th page from back
    int res;
    res = ntag21x_read4(tag, page, cdata); // Read current configuration from tag
    if (res < 0)
	return res;
    cdata[0] &= 0xf8; // Reset auth limit bits
    cdata[0] |= byte; // Set aut limit
    res = ntag21x_write(tag, page, cdata); // Write new configuration to tag
    return res;
}

/*
 * Read 16 bytes from NTAG.
 */
int
ntag21x_read(FreefareTag tag, uint8_t page, uint8_t *data)
{
    ASSERT_ACTIVE(tag);
    NTAG_ASSERT_VALID_PAGE(tag, page, false);

    // Init buffers
    BUFFER_INIT(cmd, 2);
    BUFFER_INIT(res, 16);

    // Append read 16B command to buffer
    BUFFER_APPEND(cmd, 0x30);
    BUFFER_APPEND(cmd, page);

    NTAG_TRANSCEIVE(tag, cmd, res);  // Send & receive to & from tag
    memcpy(data, res, 16);  // Copy first 4 bytes (selected page) to data output
    return 0;
}

/*
 * Read 4 bytes from NTAG
 */
int
ntag21x_read4(FreefareTag tag, uint8_t page, uint8_t *data)
{
    BUFFER_INIT(res, 16);
    int re = ntag21x_read(tag, page, res);
    memcpy(data, res, 4);
    return re;
}

/*
 * Read pages from [start,end] from NTAG
 */
int
ntag21x_fast_read(FreefareTag tag, uint8_t start_page, uint8_t end_page, uint8_t *data)
{
    ASSERT_ACTIVE(tag);
    NTAG_ASSERT_VALID_PAGE(tag, start_page, false);
    NTAG_ASSERT_VALID_PAGE(tag, end_page, false);

    // Init buffers
    BUFFER_INIT(cmd, 3);
    BUFFER_INIT(res, 4 * (end_page - start_page + 1));

    // Append read 16B command to buffer
    BUFFER_APPEND(cmd, 0x3A);
    BUFFER_APPEND(cmd, start_page);
    BUFFER_APPEND(cmd, end_page);

    NTAG_TRANSCEIVE_RAW(tag, cmd, res);  // Send & receive to & from tag

    memcpy(data, res, 4 * (end_page - start_page + 1)); // Copy first 4 bytes (selected page) to data output
    return 0;
}

int
ntag21x_fast_read4(FreefareTag tag, uint8_t page, uint8_t *data)
{
    BUFFER_INIT(res, 4);
    int re = ntag21x_fast_read(tag, page, page, res);
    memcpy(data, res, 4);
    return re;
}

/*
 * Read one way counter 3 bytes
 */
int
ntag21x_read_cnt(FreefareTag tag, uint8_t *data)
{
    ASSERT_ACTIVE(tag);

    // Init buffers
    BUFFER_INIT(cmd, 2);
    BUFFER_INIT(res, 3);

    // Append read cnt command to buffer
    BUFFER_APPEND(cmd, 0x39);
    BUFFER_APPEND(cmd, 0x02);

    NTAG_TRANSCEIVE_RAW(tag, cmd, res);  // Send & receive to & from tag

    memcpy(data, res, 3);  // Copy first 3 bytes (selected page) to data output
    return 0;
}

/*
 * Read data to the provided MIFARE tag.
 */
int
ntag21x_write(FreefareTag tag, uint8_t page, uint8_t data[4])
{
    ASSERT_ACTIVE(tag);
    NTAG_ASSERT_VALID_PAGE(tag, page, true);

    // Init buffera
    BUFFER_INIT(cmd, 6);
    BUFFER_INIT(res, 1);

    // Append write 4B command to buffer
    BUFFER_APPEND(cmd, 0xA2);
    BUFFER_APPEND(cmd, page);
    BUFFER_APPEND_BYTES(cmd, data, 4);  // Copy data to last 4 bytes of buffer

    NTAG_TRANSCEIVE(tag, cmd, res);

    return 0;
}

int
ntag21x_compatibility_write(FreefareTag tag, uint8_t page, uint8_t data[4])
{
    ASSERT_ACTIVE(tag);
    NTAG_ASSERT_VALID_PAGE(tag, page, true);

    // Init buffera
    BUFFER_INIT(cmd, 18);
    BUFFER_INIT(res, 1);

    // Append write 4B command to buffer
    BUFFER_APPEND(cmd, 0xA0);
    BUFFER_APPEND(cmd, page);
    BUFFER_APPEND_BYTES(cmd, data, 4);  // Copy data to last 4 bytes of buffer
    for (int i = 0; i < 12; i++) {
	BUFFER_APPEND(cmd, 0x00);
    }

    NTAG_TRANSCEIVE(tag, cmd, res);
    return 0;
}

/*
 * Authenticate to the provided NTAG tag.
 */
int
ntag21x_authenticate(FreefareTag tag, const NTAG21xKey key)
{
    ASSERT_ACTIVE(tag);
    BUFFER_INIT(cmd1, 5);
    BUFFER_INIT(res, 2);
    BUFFER_APPEND(cmd1, 0x1B);
    BUFFER_APPEND_BYTES(cmd1, key->data, 4); // Append key to command
    NTAG_TRANSCEIVE_RAW(tag, cmd1, res);

    //Check if authenticated (PACK must be as expected)
    bool flag_auth = true;
    for (int i = 0; i < 2; i++)
	if (res[i] != key->pack[i]) {
	    flag_auth = false;
	    break;
	}

    if (!flag_auth)
	return -1;
    // XXX Should we store the state "authenticated" in the tag struct??
    return 0;
}

bool
is_ntag21x(FreefareTag tag)
{
    return tag->type == NTAG_21x;
}

/*
 * Callback for freefare_tag_new to test presence of a ntag21x on the reader.
 */
bool
ntag21x_is_auth_supported(nfc_device *device, nfc_iso14443a_info nai)
{
    int ret;
    uint8_t cmd_step1[2];
    uint8_t res_step1[8];
    cmd_step1[0] = 0x60;
    cmd_step1[1] = 0x00;

    nfc_target pnti;
    nfc_modulation modulation = {
	.nmt = NMT_ISO14443A,
	.nbr = NBR_106
    };
    nfc_initiator_select_passive_target(device, modulation, nai.abtUid, nai.szUidLen, &pnti);
    nfc_device_set_property_bool(device, NP_EASY_FRAMING, false);
    ret = nfc_initiator_transceive_bytes(device, cmd_step1, sizeof(cmd_step1), res_step1, sizeof(res_step1), 0);
    nfc_device_set_property_bool(device, NP_EASY_FRAMING, true);
    nfc_initiator_deselect_target(device);
    return ret >= 0;
}
