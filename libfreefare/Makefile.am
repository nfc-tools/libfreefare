
AM_CFLAGS = -I. @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

lib_LTLIBRARIES = libfreefare.la

libfreefare_la_SOURCES = freefare.c \
			 mifare_classic.c \
			 mifare_ultralight.c \
			 mad.c \
			 mifare_application.c
libfreefare_la_HEADERS = freefare.h
libfreefare_ladir = $(includedir)

EXTRA_DIST = freefare_internal.h
