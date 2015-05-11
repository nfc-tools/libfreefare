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
 * 
 * $Id$
 */


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
mifare_desfire_error_lookup (uint8_t code)
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
mifare_desfire_last_pcd_error (FreefareTag tag)
{
    if (tag->tag_info->type != DESFIRE)
	return 0;

    return MIFARE_DESFIRE (tag)->last_pcd_error;
}

uint8_t
mifare_desfire_last_picc_error (FreefareTag tag)
{
    if (tag->tag_info->type != DESFIRE)
	return 0;

    return MIFARE_DESFIRE (tag)->last_picc_error;
}
