#include <sys/types.h>

#include <stdlib.h>

#include <freefare.h>

#include "freefare_internal.h"

#define EM(e) { e, #e }

static struct error_message {
    uint8_t code;
    const char *message;
} error_messages[] = {
    EM(OPERATION_OK),
    EM(NO_CHANGES),
    EM(OUT_OF_EEPROM_ERROR),
    EM(ILLEGAL_COMMAND_CODE),
    EM(INTEGRITY_ERROR),
    EM(NO_SUCH_KEY),
    EM(LENGTH_ERROR),
    EM(PERMISSION_ERROR),
    EM(PARAMETER_ERROR),
    EM(APPLICATION_NOT_FOUND),
    EM(APPL_INTEGRITY_ERROR),
    EM(AUTHENTICATION_ERROR),
    EM(ADDITIONAL_FRAME),
    EM(BOUNDARY_ERROR),
    EM(PICC_INTEGRITY_ERROR),
    EM(COMMAND_ABORTED),
    EM(PICC_DISABLED_ERROR),
    EM(COUNT_ERROR),
    EM(DUPLICATE_ERROR),
    EM(EEPROM_ERROR),
    EM(FILE_NOT_FOUND),
    EM(FILE_INTEGRITY_ERROR),
    EM(CRYPTO_ERROR),
    { 0, NULL }
};

const char *
mifare_desfire_error_lookup(uint8_t code)
{
    struct error_message *e = error_messages;
    while (e->message) {
	if (e->code == code)
	    return (e->message);
	e++;
    }

    return "Invalid error code";
}

uint8_t
mifare_desfire_last_pcd_error(FreefareTag tag)
{
    if (tag->type != MIFARE_DESFIRE)
	return 0;

    return MIFARE_DESFIRE(tag)->last_pcd_error;
}

uint8_t
mifare_desfire_last_picc_error(FreefareTag tag)
{
    if (tag->type != MIFARE_DESFIRE)
	return 0;

    return MIFARE_DESFIRE(tag)->last_picc_error;
}
