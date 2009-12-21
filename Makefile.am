
ACLOCAL_AMFLAGS = -I m4

AM_CFLAGS = -I. -std=c99 @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

lib_LTLIBRARIES = libfreefare.la

libfreefare_la_SOURCES = mifare_classic.c mad.c
libfreefare_la_HEADERS = mifare_classic.h mad.h
libfreefare_ladir = $(includedir)

pkgconfigdir = $(libdir)/pkgconfig
pkgconfig_DATA = libfreefare.pc
