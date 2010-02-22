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

#include <cutter.h>
#include <errno.h>
#include <string.h>

#include <freefare.h>
#include "freefare_internal.h"

#include "mifare_ultralight_fixture.h"

void
test_mifare_ultralight_write (void)
{
    int res;

    MifareUltralightPage initial;
    MifareUltralightPage page;
    MifareUltralightPage payload1  = { 0x12, 0x34, 0x56, 0x78 };
    MifareUltralightPage payload2  = { 0xaa, 0x55, 0x00, 0xff };

    MifareUltralightPageNumber n = 7;

    /* Read and save current value (should be { 0x00 0x00 0x00 0x00 }) */
    res = mifare_ultralight_read (tag, n, &initial);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));

    /* Write payload1 */
    res = mifare_ultralight_write (tag, n, payload1);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_write() failed"));

    /* Check it */
    res = mifare_ultralight_read (tag, n, &page);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));
    cut_assert_equal_memory (payload1, sizeof (payload1), page, sizeof (page), cut_message ("Wrong data"));

    /* Write payload2 */
    res = mifare_ultralight_write (tag, n, payload2);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_write() failed"));

    /* Check it */
    res = mifare_ultralight_read (tag, n, &page);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));
    cut_assert_equal_memory (payload2, sizeof (payload2), page, sizeof (page), cut_message ("Wrong data"));

    /* Write initial data */
    res = mifare_ultralight_write (tag, n, initial);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_write() failed"));

    /* While here check it (no reason to fail since the rest of the test passed) */
    res = mifare_ultralight_read (tag, n, &page);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));
    cut_assert_equal_memory (initial, sizeof (initial), page, sizeof (page), cut_message ("Wrong data"));
}

void
test_mifare_ultralight_invalid_page (void)
{
    int res;
    MifareUltralightPage page = { 0x00, 0x00, 0x00, 0x00 };

    res = mifare_ultralight_read (tag, 16, &page);
    cut_assert_equal_int (-1, res, cut_message ("mifare_ultralight_read() succeeded"));
    cut_assert_equal_int (EINVAL, errno, cut_message ("Wrong errno value"));

    res = mifare_ultralight_write (tag, 16, page);
    cut_assert_equal_int (-1, res, cut_message ("mifare_ultralight_write() succeeded"));
    cut_assert_equal_int (EINVAL, errno, cut_message ("Wrong errno value"));
}

void
test_mifare_ultralight_cache (void)
{
    int res;
    MifareUltralightPage page;

    res = mifare_ultralight_read (tag, 0, &page);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));

    /* Check cached pages consistency */
    for (int i = 0; i <= 3; i++) {
	cut_assert_equal_int (1, MIFARE_ULTRALIGHT(tag)->cached_pages[i], cut_message ("Wrong page cache value for tag->cached_pages[%d]", i));
    }
    for (int i = 4; i < MIFARE_ULTRALIGHT_PAGE_COUNT; i++) {
	cut_assert_equal_int (0, MIFARE_ULTRALIGHT(tag)->cached_pages[i], cut_message ("Wrong page cache value for tag->cached_pages[%d]", i));
    }
}

void
test_mifare_ultralight_cache_hit (void)
{
    int res;

    MifareUltralightPage page1;
    MifareUltralightPage page2;

    res = mifare_ultralight_read (tag, 0, &page1);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));

    res = mifare_ultralight_read (tag, 0, &page2);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));
    cut_assert_equal_memory (page1, sizeof (page1), page2, sizeof (page2), cut_message ("Wrong cached data"));
}


void
test_mifare_ultralight_cache_wrap (void)
{
    int res;
    MifareUltralightPage page;

    res = mifare_ultralight_read (tag, 15, &page);
    cut_assert_equal_int (0, res, cut_message ("mifare_ultralight_read() failed"));

    /* Check cached pages consistency */
    for (int i = 0; i <= 2; i++) {
	cut_assert_equal_int (1, MIFARE_ULTRALIGHT(tag)->cached_pages[i], cut_message ("Wrong page cache value for tag->cached_pages[%d]", i));
    }
    for (int i = 3; i <= 14; i++) {
	cut_assert_equal_int (0, MIFARE_ULTRALIGHT(tag)->cached_pages[i], cut_message ("Wrong page cache value for tag->cached_pages[%d]", i));
    }
    for (int i = 15; i < MIFARE_ULTRALIGHT_PAGE_COUNT; i++) {
	cut_assert_equal_int (1, MIFARE_ULTRALIGHT(tag)->cached_pages[i], cut_message ("Wrong page cache value for tag->cached_pages[%d]", i));
    }
}

void
test_mifare_ultralight_get_uid (void)
{
    char *uid;

    uid = mifare_ultralight_get_uid (tag);

    cut_assert_not_null (uid, cut_message ("mifare_ultralight_get_uid() failed"));
    cut_assert_equal_int (14, strlen (uid), cut_message ("Wrong UID length"));

    free (uid);
}
