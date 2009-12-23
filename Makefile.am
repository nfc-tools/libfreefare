
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I. @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

lib_LTLIBRARIES = libfreefare.la

libfreefare_la_SOURCES = mifare_classic.c mad.c mifare_application.c
libfreefare_la_HEADERS = mifare_common.h mifare_classic.h mad.h mifare_application.h
libfreefare_ladir = $(includedir)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfreefare.pc
