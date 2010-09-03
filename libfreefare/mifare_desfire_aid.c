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
 * http://www.scnf.org.uk/smartstore/LASSeO%20docs/DESFIRE%20Specification%20V1%200.pdf
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

#if defined(HAVE_BYTESWAP_H)
#  include <byteswap.h>
#endif

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

// FIXME Theorically, it should be an uint24_t ...
MifareDESFireAID
mifare_desfire_aid_new (uint32_t aid)
{
    if (aid > 0x00ffffff)
	return errno = EINVAL, NULL;

    MifareDESFireAID res;
    uint32_t aid_le = htole32 (aid);

    if ((res = malloc (sizeof (*res)))) {
	memcpy(res->data, ((uint8_t*)&aid_le), 3);
    }

    return res;
}

// This function ease the MifareDESFireAID creation using a Mifare Classic AID (see MIFARE Application Directory document - section 3.10 MAD and MIFARE DESFire)
MifareDESFireAID
mifare_desfire_aid_new_with_mad_aid (MadAid mad_aid, uint8_t n)
{
    if (n > 0x0f)
	return errno = EINVAL, NULL;

    return mifare_desfire_aid_new (0xf00000 | (mad_aid.function_cluster_code << 12) | (mad_aid.application_code << 4) | n);
}

