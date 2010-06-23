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

#include <cutter.h>

#include <freefare.h>

const uint8_t shortdata[8]  = "elephant";
const uint8_t eshortdata[11] = "\x03" "\x08" "elephant" "\xfe";

			    /*
			     * Many thanks to Charles Baudelaire for helping me
			     * test things and helping you realize your f**king
			     * OS / compiler does not support UTF-8 ;-)
			     */
const uint8_t longdata[660] =  "Dans une terre grasse et pleine d'escargots\n"
                            "Je veux creuser moi-même une fosse profonde,\n"
		            "Où je puisse à loisir étaler mes vieux os\n"
		            "Et dormir dans l'oubli comme un requin dans l'onde.\n"
		            "Je hais les testaments et je hais les tombeaux;\n"
		            "Plutôt que d'implorer une larme du monde,\n"
		            "Vivant, j'aimerais mieux inviter les corbeaux\n"
		            "À saigner tous les bouts de ma carcasse immonde.\n"
		            "Ô vers! noirs compagnons sans oreille et sans yeux,\n"
		            "Voyez venir à vous un mort libre et joyeux;\n"
		            "Philosophes viveurs, fils de la pourriture,\n"
		            "À travers ma ruine allez donc sans remords,\n"
		            "Et dites-moi s'il est encor quelque torture\n"
		            "Pour ce vieux corps sans âme et mort parmi les morts!\n";

const uint8_t elongdata[665] = "\x07" "\xff\x02\x94"
                            "Dans une terre grasse et pleine d'escargots\n"
                            "Je veux creuser moi-même une fosse profonde,\n"
		            "Où je puisse à loisir étaler mes vieux os\n"
		            "Et dormir dans l'oubli comme un requin dans l'onde.\n"
		            "Je hais les testaments et je hais les tombeaux;\n"
		            "Plutôt que d'implorer une larme du monde,\n"
		            "Vivant, j'aimerais mieux inviter les corbeaux\n"
		            "À saigner tous les bouts de ma carcasse immonde.\n"
		            "Ô vers! noirs compagnons sans oreille et sans yeux,\n"
		            "Voyez venir à vous un mort libre et joyeux;\n"
		            "Philosophes viveurs, fils de la pourriture,\n"
		            "À travers ma ruine allez donc sans remords,\n"
		            "Et dites-moi s'il est encor quelque torture\n"
		            "Pour ce vieux corps sans âme et mort parmi les morts!\n"
			    "\xfe";

void
test_tlv_encode_short (void)
{
    uint8_t *res;
    size_t osize;

    res = tlv_encode (3, shortdata, sizeof (shortdata), &osize);
    cut_assert_equal_int (sizeof (eshortdata), osize, cut_message ("Wrong encoded message length."));
    cut_assert_equal_int (3, res[0], cut_message ("Wrong type"));
    cut_assert_equal_int (sizeof (shortdata), res[1], cut_message ("Wrong value length"));
    cut_assert_equal_memory (eshortdata, sizeof (eshortdata), res, osize, cut_message ("Wrong encoded value"));
    free (res);
}

void
test_tlv_encode_long (void)
{
    uint8_t *res;
    size_t osize;

    res = tlv_encode (7, longdata, sizeof (longdata), &osize);
    cut_assert_equal_int (sizeof (elongdata), osize, cut_message ("Wrong encoded message length."));
    cut_assert_equal_int (7, res[0], cut_message ("Wrong type"));
    cut_assert_equal_int (0xff, res[1], cut_message ("Wrong value length"));
    cut_assert_equal_int (0x02, res[2], cut_message ("Wrong value length"));
    cut_assert_equal_int (0x94, res[3], cut_message ("Wrong value length"));
    cut_assert_equal_memory (elongdata, sizeof (elongdata), res, osize, cut_message ("Wrong encoded value"));
    free (res);
}

void
test_tlv_decode_short (void)
{
    uint8_t *res;
    uint16_t size;
    uint8_t type;

    res = tlv_decode (eshortdata, &type, &size);
    cut_assert_equal_int (3, type, cut_message ("Wrong type"));
    cut_assert_equal_int (sizeof (shortdata), size, cut_message ("Wrong value length"));
    cut_assert_equal_memory (shortdata, sizeof (shortdata), res, size, cut_message ("Wrong decoded value"));
    free (res);
}

void
test_tlv_decode_long (void)
{
    uint8_t *res;
    uint16_t size;
    uint8_t type;

    res = tlv_decode (elongdata, &type, &size);
    cut_assert_equal_int (7, type, cut_message ("Wrong type"));
    cut_assert_equal_int (sizeof (longdata), size, cut_message ("Wrong value length"));
    cut_assert_equal_memory (longdata, sizeof (longdata), res, size, cut_message ("Wrong decoded value"));
    free (res);
}

void
test_tlv_rfu (void)
{
    uint8_t *data = malloc (0xffff);
    cut_assert_not_null (data, cut_message ("Out of memory"));

    uint8_t *res = tlv_encode (7, data, 0xffff, NULL);
    cut_assert_null (res, cut_message ("Size reserved for future use"));

    free (data);
}
