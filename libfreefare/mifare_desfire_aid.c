/*
 * This implementation was written based on information provided by the
 * following document:
 *
 * Mifare DESFire Specification by LASSeO
 * Version 1.0 - 29'th September 2009
 * http://www.scnf.org.uk/smartstore/LASSeO%20docs/DESFIRE%20Specification%20V1%200.pdf
 */

#if defined(HAVE_CONFIG_H)
#  include "config.h"
#endif

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

#include <errno.h>
#include <stdlib.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

// Theorically, it should be an uint24_t ...
MifareDESFireAID
mifare_desfire_aid_new(uint32_t aid)
{
    if (aid > 0x00ffffff)
	return errno = EINVAL, NULL;

    MifareDESFireAID res;
    uint32_t aid_le = htole32(aid);

    if ((res = malloc(sizeof(*res)))) {
	memcpy(res->data, ((uint8_t *)&aid_le), 3);
    }

    return res;
}

// This function ease the MifareDESFireAID creation using a Mifare Classic AID (see MIFARE Application Directory document - section 3.10 MAD and MIFARE DESFire)
MifareDESFireAID
mifare_desfire_aid_new_with_mad_aid(MadAid mad_aid, uint8_t n)
{
    if (n > 0x0f)
	return errno = EINVAL, NULL;

    return mifare_desfire_aid_new(0xf00000 | (mad_aid.function_cluster_code << 12) | (mad_aid.application_code << 4) | n);
}

uint32_t
mifare_desfire_aid_get_aid(MifareDESFireAID aid)
{
    return aid->data[0] | (aid->data[1] << 8) | (aid->data[2] << 16);
}
