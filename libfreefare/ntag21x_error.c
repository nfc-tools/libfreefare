#include <sys/types.h>

#include <stdlib.h>

#include <freefare.h>

#include "freefare_internal.h"

#define EM(e) { e, #e }

static struct ntag21x_error_message {
    uint8_t code;
    const char *message;
} ntag21x_error_messages[] = {
    EM(OPERATION_OK),
    EM(TAG_INFO_MISSING_ERROR),
    EM(UNKNOWN_TAG_TYPE_ERROR),
    { 0, NULL }
};

const char *
ntag21x_error_lookup(uint8_t code)
{
    struct ntag21x_error_message *e = ntag21x_error_messages;
    while (e->message) {
    if (e->code == code)
        return (e->message);
    e++;
    }

    return "Invalid error code";
}

uint8_t
ntag21x_last_error(FreefareTag tag)
{
    if (tag->type != NTAG_21x)
	    return 0;

    return NTAG_21x(tag)->last_error;
}
