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

#include "config.h"
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <endian.h>

#include <freefare.h>

/*
 * TLV (Type Length Value) Manipulation Functions.
 */

/*
 * Encode data stream into TLV.
 */
uint8_t *
tlv_encode (const uint8_t type, const uint8_t *istream, uint16_t isize, size_t *osize)
{
    uint8_t *res;
    off_t n = 0;

    if (osize)
	*osize = 0;

    if (isize == 0xffff) /* RFU */
	return NULL;

    if ((res = malloc (1 + ((isize > 254) ? 3 : 1) + isize))) {
	res[n++] = type;

	if (isize > 254) {
	    res[n++] = 0xff;
	    uint16_t size_be = htobe16 (isize);
	    memcpy (res + n, &size_be, sizeof (uint16_t));
	    n += 2;
	} else {
	    res[n++] = (uint8_t)isize;
	}

	memcpy (res + n, istream, isize);
	if (osize)
	    *osize = isize + n;
    }
    return res;
}

/*
 * Decode TLV from data stream.
 */
uint8_t *
tlv_decode (const uint8_t *istream, uint8_t *type, uint16_t *size)
{
    size_t s;
    off_t o = 1;
    uint8_t *res = NULL;

    if (type)
	*type = istream[0];

    if (istream[1] == 0xff) {
	uint16_t be_size;
	memcpy (&be_size, istream + 2, sizeof (uint16_t));
	s = be16toh(be_size);
	o += 3;
    } else {
	s = istream[1];
	o += 1;
    }
    if (size) {
	*size = s;
    }

    if ((res = malloc (s))) {
	memcpy (res, istream + o, s);
    }
    return res;
}
