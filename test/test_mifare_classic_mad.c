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

#include <freefare.h>

#include "mifare_classic_fixture.h"

void
test_mifare_classic_mad (void)
{
    MifareClassicKey key_a_transport = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    MifareClassicKey key_b_sector_00 = { 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff };
    MifareClassicKey key_b_sector_10 = { 0x1a, 0x98, 0x2c, 0x7e, 0x45 ,0x9a };
    MifareClassicBlock tb;
    Mad mad;
    int res;

    /*  __  __   _   ___      _
     * |  \/  | /_\ |   \__ _/ |
     * | |\/| |/ _ \| |) \ V / |
     * |_|  |_/_/ \_\___/ \_/|_|
     */

    mad = mad_new (1);
    cut_assert_not_null (mad, cut_message ("mad_new() failed"));

    // Prepare sector 0x00 for writing a MAD.
    res = mifare_classic_authenticate (tag, 0x00, key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    mifare_classic_trailer_block (&tb, key_a_transport, 00, 00, 00, 06, 0x00, key_b_sector_00);

    res = mifare_classic_write (tag, 0x03, tb);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    // Write the empty MAD
    res = mad_write (tag, mad, key_b_sector_00, NULL);
    cut_assert_equal_int (0, res, cut_message ("mad_write() failed"));


    // Check the empty MAD
    MifareClassicBlock ref_01 = { 0xce, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MifareClassicBlock ref_02 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MifareClassicBlock data;

    res = mifare_classic_authenticate (tag, 0x01, mad_public_key_a, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    res = mifare_classic_read (tag, 0x01, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_01, sizeof (ref_01), data, sizeof (data), cut_message ("Wrong data"));

    res = mifare_classic_read (tag, 0x02, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_02, sizeof (ref_02), data, sizeof (data), cut_message ("Wrong data"));

    Mad mad2 = mad_read (tag);
    cut_assert_not_null (mad2, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (mad, sizeof (mad), mad2, sizeof (mad2), cut_message ("Wrong MAD"));

    const char application_data[] = "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> "
				    "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> "
				    "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> "
				    "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> "
				    "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> "
				    "APPLICATION DATA >> APPLICATION DATA >> APPLICATION DATA >> ";

    MadAid aid = {
	.function_cluster_code = 0x01,
	.application_code      = 0x12
    };

    // Write some data in the application
    MifareClassicSectorNumber *sectors = mifare_application_alloc (mad, aid, sizeof (application_data));
    cut_assert_not_null (sectors, cut_message ("mifare_application_alloc() failed"));
    free (sectors);

    res = mad_write (tag, mad, key_b_sector_00, NULL);
    cut_assert_equal_int (0, res, cut_message ("mad_write() failed"));

    ssize_t s = mad_application_write (tag, mad, aid, &application_data, sizeof (application_data), key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (sizeof (application_data), s, cut_message ("mad_application_write() failed"));

    char read_buf[500];

    // Read it again
    s = mad_application_read (tag, mad, aid, read_buf, sizeof (application_data), key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (sizeof (application_data), s, cut_message ("mad_application_read() failed"));
    cut_assert_equal_memory (application_data, sizeof (application_data), read_buf, s, cut_message ("Wrong application data"));

    mad_free (mad);
    mad_free (mad2);

    // Revert to the transport configuration
    res = mifare_classic_authenticate (tag, 0x00, key_b_sector_00, MFC_KEY_B);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
    res = mifare_classic_format_sector (tag, 0x00);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_format_sector() failed"));

    /*  __  __   _   ___      ___
     * |  \/  | /_\ |   \__ _|_  )
     * | |\/| |/ _ \| |) \ V // /
     * |_|  |_/_/ \_\___/ \_//___|
     */
    if (freefare_get_tag_type (tag) != CLASSIC_4K) {
	cut_omit ("MADv2 requires a MIFARE Classic 4K to be tested");
    }

    mad = mad_new (2);
    cut_assert_not_null (mad, cut_message ("mad_new() failed"));

    // Prepare sector 0x00 for writing a MAD.
    res = mifare_classic_authenticate (tag, 0x00, key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    mifare_classic_trailer_block (&tb, key_a_transport, 00, 00, 00, 06, 0x00, key_b_sector_00);

    res = mifare_classic_write (tag, 0x03, tb);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    // Prepare sector 0x10 for writing a MAD.
    res = mifare_classic_authenticate (tag, 0x40, key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    mifare_classic_trailer_block (&tb, key_a_transport, 00, 00, 00, 06, 0x00, key_b_sector_10);

    res = mifare_classic_write (tag, 0x43, tb);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_write() failed"));

    // Write the empty MAD
    res = mad_write (tag, mad, key_b_sector_00, key_b_sector_10);
    cut_assert_equal_int (0, res, cut_message ("mad_write() failed"));

    // Check the empty MAD

    res = mifare_classic_authenticate (tag, 0x01, mad_public_key_a, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    res = mifare_classic_read (tag, 0x01, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_01, sizeof (ref_01), data, sizeof (data), cut_message ("Wrong data"));

    res = mifare_classic_read (tag, 0x02, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_02, sizeof (ref_02), data, sizeof (data), cut_message ("Wrong data"));

    MifareClassicBlock ref_40 = { 0x16, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MifareClassicBlock ref_41 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };
    MifareClassicBlock ref_42 = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
				  0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

    res = mifare_classic_authenticate (tag, 0x40, mad_public_key_a, MFC_KEY_A);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));

    res = mifare_classic_read (tag, 0x40, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_40, sizeof (ref_01), data, sizeof (data), cut_message ("Wrong data"));

    res = mifare_classic_read (tag, 0x41, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_41, sizeof (ref_02), data, sizeof (data), cut_message ("Wrong data"));

    res = mifare_classic_read (tag, 0x42, &data);
    cut_assert_equal_int (0, res, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (ref_42, sizeof (ref_02), data, sizeof (data), cut_message ("Wrong data"));


    mad2 = mad_read (tag);
    cut_assert_not_null (mad2, cut_message ("mad_read() failed"));
    cut_assert_equal_memory (mad, sizeof (mad), mad2, sizeof (mad2), cut_message ("Wrong MAD"));

    // Write some data in the application
    sectors = mifare_application_alloc (mad, aid, sizeof (application_data));
    cut_assert_not_null (sectors, cut_message ("mifare_application_alloc() failed"));
    free (sectors);

    res = mad_write (tag, mad, key_b_sector_00, key_b_sector_10);
    cut_assert_equal_int (0, res, cut_message ("mad_write() failed"));

    s = mad_application_write (tag, mad, aid, &application_data, sizeof (application_data), key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (sizeof (application_data), s, cut_message ("mad_application_write() failed"));

    // Read it again
    s = mad_application_read (tag, mad, aid, read_buf, sizeof (application_data), key_a_transport, MFC_KEY_A);
    cut_assert_equal_int (sizeof (application_data), s, cut_message ("mad_application_read() failed"));
    cut_assert_equal_memory (application_data, sizeof (application_data), read_buf, s, cut_message ("Wrong application data"));

    mad_free (mad);
    mad_free (mad2);

    // Revert to the transport configuration
    res = mifare_classic_authenticate (tag, 0x00, key_b_sector_00, MFC_KEY_B);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
    res = mifare_classic_format_sector (tag, 0x00);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_format_sector() failed"));

    res = mifare_classic_authenticate (tag, 0x40, key_b_sector_10, MFC_KEY_B);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_authenticate() failed"));
    res = mifare_classic_format_sector (tag, 0x10);
    cut_assert_equal_int (0, res, cut_message ("mifare_classic_format_sector() failed"));

}
