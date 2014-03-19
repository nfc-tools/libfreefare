/*-
 * Copyright (C) 2009, Romain Tartiere, Romuald Conty.
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
 * This implementation was written based on information provided by the
 * following document:
 *
 * /dev/brain
 */
#include "config.h"

#include <errno.h>
#include <string.h>
#include <stdlib.h>

#include <freefare.h>
#include "freefare_internal.h"

#define FIRST_SECTOR 1

int	 aidcmp (const MadAid left, const MadAid right);
size_t	 count_aids (const Mad mad, const MadAid aid);

/*
 * Get the number of sectors allocated in the MAD for the provided application.
 */
size_t
count_aids (const Mad mad, const MadAid aid)
{
    size_t result = 0;

    MifareClassicSectorNumber s_max = (mad_get_version (mad) == 1) ? 0x0f : 0x27;

    /* Count application sectors */
    MadAid c_aid;
    for (MifareClassicSectorNumber s = FIRST_SECTOR; s <= s_max; s++) {
	mad_get_aid (mad, s, &c_aid);
	if (0 == aidcmp (aid, c_aid)) {
	    result++;
	}
    }

    return result;
}

/*
 * Compare two application identifiers.
 */
inline int
aidcmp (const MadAid left, const MadAid right)
{
    return ((left.function_cluster_code - right.function_cluster_code) << 8) | (left.application_code - right.application_code);
}


/*
 * Card publisher functions (MAD owner).
 */

/*
 * Allocates a new application into a MAD.
 */
MifareClassicSectorNumber *
mifare_application_alloc (Mad mad, MadAid aid, size_t size)
{
    uint8_t sector_map[40];
    MifareClassicSectorNumber sector;
    MadAid sector_aid;
    MifareClassicSectorNumber *res = NULL;
    ssize_t s = size;

    /*
     * Ensure the card does not already have the application registered.
     */
    MifareClassicSectorNumber *found;
    if ((found = mifare_application_find (mad, aid))) {
	free (found);
	return NULL;
    }

    for (size_t i = 0; i < sizeof (sector_map); i++)
	sector_map[i] = 0;

    /*
     * Try to minimize lost space and allocate as many large pages as possible
     * when the target is a Mifare Classic 4k.
     */
    MadAid free_aid = { 0x00, 0x00 };
    if (mad_get_version (mad) == 2) {
	sector = 32;
	while ((s >= 12*16) && sector < 40) {
	    mad_get_aid (mad, sector, &sector_aid);
	    if (0 == aidcmp (sector_aid, free_aid)) {
		sector_map[sector] = 1;
		s -= 15*16;
	    }
	    sector++;
	}
    }

    sector = FIRST_SECTOR;
    MifareClassicSectorNumber s_max = (mad_get_version (mad) == 1) ? 15 : 31;
    while ((s > 0) && (sector <= s_max)) {
	if (mad_sector_reserved (sector))
	    continue;
	mad_get_aid (mad, sector, &sector_aid);
	if (0 == aidcmp (sector_aid, free_aid)) {
	    sector_map[sector] = 1;
	    s -= 3*16;
	}
	sector++;
    }

    /*
     * Ensure the remaining free space is suficient before destroying the MAD.
     */
    if (s > 0)
	return NULL;

    int n = 0;
    for (size_t i = FIRST_SECTOR; i < sizeof (sector_map); i++)
	if (sector_map[i])
	    n++;

    if (!(res = malloc (sizeof (*res) * (n+1))))
	return NULL;

    n = 0;
    for (size_t i = FIRST_SECTOR; i < sizeof (sector_map); i++)
	if (sector_map[i]) {
	    res[n] = i;
	    mad_set_aid (mad, i, aid);
	    n++;
	}

    res[n] = 0;

    /* Return the list of allocated sectors */
    return res;
}

/*
 * Remove an application from a MAD.
 */
int
mifare_application_free (Mad mad, MadAid aid)
{
    MifareClassicSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareClassicSectorNumber *p = sectors;
    MadAid free_aid = { 0x00, 0x00 };

    /* figure out if malloc() in mifare_application_find() failed */
    if (sectors == NULL) return count_aids (mad, aid) ? -1 : 0;

    while (*p) {
	mad_set_aid (mad, *p, free_aid);
	p++;
    }

    free (sectors);

    return 0;
}


/*
 * Application owner functions.
 */

/*
 * Get all sector numbers of an application from the provided MAD.
 */
MifareClassicSectorNumber *
mifare_application_find (Mad mad, MadAid aid)
{
    MifareClassicSectorNumber *res = NULL;
    size_t res_count = count_aids (mad, aid);

    if (res_count)
	res = malloc (sizeof (*res) * (res_count + 1));

    size_t r = FIRST_SECTOR, w = 0;
    if (res) {
	/* Fill in the result */
	MadAid c_aid;
	while (w < res_count) {
	    mad_get_aid (mad, r, &c_aid);
	    if (0 == aidcmp (c_aid, aid)) {
		res[w++] = r;
	    }
	    r++;
	}
	res[w] = 0;
    }

    return res;
}

ssize_t
mifare_application_read (MifareTag tag, Mad mad, const MadAid aid, void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    ssize_t res = 0;

    MifareClassicSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareClassicSectorNumber *s = sectors;

    if (!sectors)
	return errno = EBADF, -1;

    while (*s && nbytes && (res >= 0)) {
	MifareClassicBlockNumber first_block = mifare_classic_sector_first_block (*s);
	MifareClassicBlockNumber last_block  = mifare_classic_sector_last_block (*s);

	MifareClassicBlockNumber b = first_block;
	MifareClassicBlock block;

	if (mifare_classic_authenticate (tag, first_block, key, key_type) < 0) {
	    res = -1;
	    break;
	}

	while ((b < last_block) && nbytes) {
	    size_t n = MIN (nbytes, 16);

	    if (mifare_classic_read (tag, b, &block) < 0) {
		res = -1;
		break;
	    }
	    memcpy ((uint8_t *)buf + res, &block, n);

	    nbytes -= n;
	    res += n;

	    b++;
	}

	s++;
    }

    free (sectors);
    return res;
}

ssize_t
mifare_application_write (MifareTag tag, Mad mad, const MadAid aid, const void *buf, size_t nbytes, const MifareClassicKey key, const MifareClassicKeyType key_type)
{
    ssize_t res = 0;

    MifareClassicSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareClassicSectorNumber *s = sectors;

    if (!sectors) {
	/* mifare_application_find may also fail if malloc() fails */
	if (errno != ENOMEM) errno = EBADF;
	return -1;
    }

    while (*s && nbytes && (res >= 0)) {
	MifareClassicBlockNumber first_block = mifare_classic_sector_first_block (*s);
	MifareClassicBlockNumber last_block  = mifare_classic_sector_last_block (*s);

	MifareClassicBlockNumber b = first_block;
	MifareClassicBlock block;

	if (mifare_classic_authenticate (tag, first_block, key, key_type) < 0) {
	    res = -1;
	    break;
	}

	while ((b < last_block) && nbytes) {
	    size_t n = MIN (nbytes, 16);
	    // Avoid overwriting existing data with uninitialized memory.
	    if (n < 16) {
		if (mifare_classic_read (tag, b, &block) < 0) {
		    res = -1;
		    break;
		}
	    }

	    memcpy (&block, (uint8_t *)buf + res, n);
	    if (mifare_classic_write (tag, b, block) < 0) {
		res = -1;
		break;
	    }

	    nbytes -= n;
	    res += n;

	    b++;
	}

	s++;
    }

    free (sectors);
    return res;

}
