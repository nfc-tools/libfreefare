AC_INIT([libfreefare], [0.0.0])

AC_CONFIG_MACRO_DIR([m4])

AC_PROG_CC
AC_PROG_CXX

AC_PROG_LIBTOOL

AC_CONFIG_HEADERS([config.h])

AM_INIT_AUTOMAKE

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_INLINE
AC_HEADER_STDBOOL
AC_TYPE_INT16_T
AC_TYPE_INT32_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_SIZE_T

# Checks for library functions.
AC_FUNC_MALLOC
AC_FUNC_REALLOC
AC_CHECK_FUNCS([memset])

AC_CHECK_HEADERS([endian.h sys/endian.h])
if test $ac_cv_header_endian_h = "no" -a $ac_cv_header_sys_endian_h = "no"; then
  AC_MSG_ERROR(["Can't locate header endian.h."]);
fi

CFLAGS="$CFLAGS -std=c99"

# Checks for pkg-config modules.
PKG_CHECK_MODULES([LIBNFC], [libnfc], [], [AC_MSG_ERROR([libnfc is mandatory.])])

PKG_CONFIG_REQUIRES="libnfc"
AC_SUBST([PKG_CONFIG_REQUIRES])

AC_OUTPUT([Makefile libfreefare/Makefile libfreefare.pc])

