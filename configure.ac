AC_INIT([libfreefare], [0.1.0])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CXX

AC_PROG_LIBTOOL

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Debug support (default:no)
AC_ARG_ENABLE([debug],AS_HELP_STRING([--enable-debug],[Enable debug output]),[enable_debug=$enableval],[enable_debug="no"])
if test x"$enable_debug" = xyes; then
    AC_CHECK_LIB([util], [hexdump], [has_libutil=yes], [has_libutil=no])
fi
AM_CONDITIONAL(WITH_DEBUG, [test x"$enable_debug" = xyes])
AM_CONDITIONAL(HAS_LIBUTIL, [test x"$has_libutil" = xyes])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_OFF_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_SIZE_T
AC_TYPE_SSIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC

AC_CHECK_HEADERS([sys/types.h])
AC_CHECK_FUNCS([memset letoh32 htole32 pow strerror])

AC_CHECK_HEADERS([endian.h sys/endian.h])
if test $ac_cv_header_endian_h = "no" -a $ac_cv_header_sys_endian_h = "no"; then
  AC_MSG_ERROR(["Can't locate header endian.h."]);
fi

AC_CHECK_HEADERS([byteswap.h])

AC_DEFINE([_XOPEN_SOURCE], [600], [Define to 500 if Single Unix conformance is wanted, 600 for sixth revision.])
AC_DEFINE([_BSD_SOURCE], [1], [Define on BSD to activate all library features])

CFLAGS="$CFLAGS -std=c99"

# Crypto functions for MIFARE DesFire support are provided by OpenSSL.
AC_CHECK_LIB([ssl], [DES_ecb_encrypt], [], [AC_MSG_ERROR([Cannot find libssl.])])
AC_CHECK_HEADER([openssl/des.h], [], [AC_MSG_ERROR([Cannot find libssl headers.])])

# Checks for pkg-config modules.
LIBNFC_REQUIRED_VERSION=1.3.4
PKG_CHECK_MODULES([LIBNFC], [libnfc >= $LIBNFC_REQUIRED_VERSION], [], [AC_MSG_ERROR([libnfc >= $LIBNFC_REQUIRED_VERSION is mandatory.])])

PKG_CONFIG_REQUIRES="libnfc"
AC_SUBST([PKG_CONFIG_REQUIRES])

CUTTER_REQUIRED_VERSION=1.1.2
m4_ifdef([AC_CHECK_CUTTER], [AC_CHECK_CUTTER([>= $CUTTER_REQUIRED_VERSION])], [ac_cv_use_cutter="no"])
if test x$ac_cv_with_cutter = xyes -a x$ac_cv_use_cutter = xno; then
    AC_MSG_ERROR([cutter >= $CUTTER_REQUIRED_VERSION is mandatory.])
fi
AM_CONDITIONAL([WITH_CUTTER], [test "$ac_cv_use_cutter" != "no"])

m4_ifdef([AC_CHECK_COVERAGE], [AC_CHECK_COVERAGE])

if test x$ac_cv_enable_coverage = xyes; then
    CFLAGS="$CFLAGS -O0 -fprofile-arcs -ftest-coverage"
fi

AC_OUTPUT([Makefile
	   contrib/Makefile
	   contrib/libutil/Makefile
	   examples/Makefile
	   libfreefare/Makefile
	   libfreefare.pc
	   test/Makefile])

