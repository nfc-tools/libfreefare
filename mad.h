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
#ifndef __MIFARE_APPLICATION_DIRECTORY_H__
#define __MIFARE_APPLICATION_DIRECTORY_H__

#include "mifare_classic.h"

typedef uint8_t MifareSector;

struct mad;
typedef struct mad *Mad;

Mad	 mad_new (uint8_t version);
Mad	 mad_read (MifareClassicTag tag);
int	 mad_write (MifareClassicTag tag, Mad mad, MifareClassicKey key_b_sector_00, MifareClassicKey key_b_sector_10);
int	 mad_get_version (Mad mad);
void	 mad_set_version (Mad mad, uint8_t version);
MifareSector mad_get_card_publisher_sector(Mad mad);
int	 mad_set_card_publisher_sector(Mad mad, MifareSector cps);
int	 mad_get_aid(Mad mad, MifareSector sector, uint8_t *function_cluster_code, uint8_t *application_code);
int	 mad_set_aid(Mad mad, MifareSector sector, uint8_t function_cluster_code, uint8_t application_code);
void	 mad_free (Mad mad);

#endif /* !__MIFARE_APPLICATION_DIRECTORY_H__ */
