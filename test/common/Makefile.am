# $Id$

INCLUDES = $(CUTTER_CFLAGS) -I$(top_srcdir)/libfreefare
AM_CFLAGS = @LIBNFC_CFLAGS@

noinst_LTLIBRARIES = \
		     libtestcommon.la

libtestcommon_la_SOURCES = mifare_desfire_auto_authenticate.c \
			   mifare_desfire_auto_authenticate.h
