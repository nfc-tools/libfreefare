/*-
 * Copyright (C) 2011 Glenn Ergeerts.
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

#ifndef __CONFIG_WINDOWS_H__
#define __CONFIG_WINDOWS_H__

#cmakedefine WITH_DEBUG

#include <winsock2.h>

#define htole32(x) (x)
#define le32toh(x) (x)
#define le16toh(x) (x)
#define htobe16(x) htons(x)
#define be16toh(x) ntohs(x)

#define ENOTSUP WSAEOPNOTSUPP

#cmakedefine PACKAGE_NAME "@PACKAGE_NAME@"
#cmakedefine PACKAGE_VERSION "@PACKAGE_VERSION@"
#cmakedefine PACKAGE_STRING "@PACKAGE_STRING@"
#cmakedefine _XOPEN_SOURCE @_XOPEN_SOURCE@
#cmakedefine SYSCONFDIR "@SYSCONFDIR@"

#endif /* !__CONFIG_WINDOWS_H__ */
