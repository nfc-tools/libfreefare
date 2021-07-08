
#ifndef __CONFIG_POSIX_H__
#define __CONFIG_POSIX_H__

#cmakedefine _XOPEN_SOURCE @_XOPEN_SOURCE@

#cmakedefine HAVE_SYS_ENDIAN_H @_HAVE_SYS_ENDIAN_H@
#cmakedefine HAVE_ENDIAN_H @_HAVE_ENDIAN_H@
#cmakedefine HAVE_BYTESWAP_H @_HAVE_BYTESWAP_H@
#cmakedefine HAVE_COREFOUNDATION_COREFOUNDATION_H @_HAVE_COREFOUNDATION_COREFOUNDATION_H@

#cmakedefine PACKAGE_NAME "@PACKAGE_NAME@"
#cmakedefine PACKAGE_VERSION "@PACKAGE_VERSION@"
#cmakedefine PACKAGE_STRING "@PACKAGE_STRING@"
#cmakedefine _XOPEN_SOURCE @_XOPEN_SOURCE@
#cmakedefine SYSCONFDIR "@SYSCONFDIR@"

#ifdef HAVE_ENDIAN_H
	#define _DEFAULT_SOURCE
#endif

#endif /* !__CONFIG_POSIX_H__ */

