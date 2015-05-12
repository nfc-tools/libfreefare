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
 */

#ifndef _MIFARE_DESFIRE_AUTO_AUTHENTICATE_H
#define _MIFARE_DESFIRE_AUTO_AUTHENTICATE_H

extern uint8_t key_data_null[8];
extern uint8_t key_data_des[8];
extern uint8_t key_data_3des[16];
extern uint8_t key_data_aes[16];
extern uint8_t key_data_3k3des[24];
extern const uint8_t key_data_aes_version;

void		 mifare_desfire_auto_authenticate (FreefareTag tag, uint8_t key_no);

#endif
