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

#include <stdlib.h>

#include <freefare.h>

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

    MifareSectorNumber s_max = (mad_get_version (mad) == 1) ? 0x0f : 0x27;

    /* Count application sectors */
    MadAid c_aid;
    for (MifareSectorNumber s = FIRST_SECTOR; s <= s_max; s++) {
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
MifareSectorNumber *
mifare_application_alloc (Mad mad, MadAid aid, size_t size)
{
    uint8_t sector_map[40];
    MifareSectorNumber sector;
    MadAid sector_aid;
    MifareSectorNumber *res = NULL;
    ssize_t s = size;

    /*
     * Ensure the card does not already have the application registered.
     */
    MifareSectorNumber *found;
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
    MifareSectorNumber s_max = (mad_get_version (mad) == 1) ? 15 : 31;
    while ((s > 0) && (sector <= s_max)) {
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

    if (!(res = malloc (n+1)))
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
void
mifare_application_free (Mad mad, MadAid aid)
{
    MifareSectorNumber *sectors = mifare_application_find (mad, aid);
    MifareSectorNumber *p = sectors;
    MadAid free_aid = { 0x00, 0x00 };
    while (*p) {
	mad_set_aid (mad, *p, free_aid);
	p++;
    }

    free (sectors);
}


/*
 * Application owner functions.
 */

/*
 * Get all sector numbers of an application from the provided MAD.
 */
MifareSectorNumber *
mifare_application_find (Mad mad, MadAid aid)
{
    MifareSectorNumber *res = NULL;
    size_t res_count = count_aids (mad, aid);

    if (res_count)
	res = malloc (sizeof (*res) * res_count + 1);

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

