# $Id$

INCLUDES = $(CUTTER_CFLAGS) -I$(top_srcdir)/libfreefare
LIBS = $(CUTTER_LIBS)


AM_CFLAGS = @LIBNFC_CFLAGS@

if WITH_CUTTER

TESTS = run-test.sh
TESTS_ENVIRONMENT = NO_MAKE=yes CUTTER="$(CUTTER)"

noinst_LTLIBRARIES = \
		     test_mad.la \
		     test_mifare_classic.la \
		     test_mifare_classic_application.la \
		     test_mifare_classic_create_trailer_block.la \
		     test_mifare_classic_sector_boundaries.la \
		     test_mifare_ultralight.la \
		     test_tlv.la

AM_LDFLAGS = -module -rpath $(libdir) -avoid-version -no-undefined

test_mad_la_SOURCES = test_mad.c
test_mad_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_la_SOURCES = test_mifare_classic.c \
				 mifare_classic_fixture.c \
				 mifare_classic_fixture.h
test_mifare_classic_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_application_la_SOURCES = test_mifare_classic_application.c
test_mifare_classic_application_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_sector_boundaries_la_SOURCES = test_mifare_classic_sector_boundaries.c
test_mifare_classic_sector_boundaries_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_create_trailer_block_la_SOURCES = test_mifare_classic_create_trailer_block.c
test_mifare_classic_create_trailer_block_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_ultralight_la_SOURCES = test_mifare_ultralight.c \
				    mifare_ultralight_fixture.c \
				    mifare_ultralight_fixture.h
test_mifare_ultralight_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_tlv_la_SOURCES = test_tlv.c
test_tlv_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

echo-cutter:
	@echo $(CUTTER)

EXTRA_DIST = run-test.sh

endif
