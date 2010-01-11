# $Id$

INCLUDES = $(CUTTER_CFLAGS) -I$(top_srcdir)/libfreefare
LIBS = $(CUTTER_LIBS)

if WITH_CUTTER

TESTS = run-test.sh
TESTS_ENVIRONMENT = NO_MAKE=yes CUTTER="$(CUTTER)"

noinst_LTLIBRARIES = \
		     test_mad.la \
		     test_mifare_classic.la \
		     test_mifare_classic_create_trailer_block.la \
		     test_mifare_classic_application.la

AM_LDFLAGS = -module -rpath $(libdir) -avoid-version -no-undefined

test_mad_la_SOURCES = test_mad.c
test_mad_la_LIBADD = $(top_srcdir)/libfreefare/libfreefare.la

test_mifare_classic_la_SOURCES = test_mifare_classic.c \
				 mifare_classic_fixture.c
test_mifare_classic_la_LIBADD = $(top_srcdir)/libfreefare/libfreefare.la

test_mifare_classic_create_trailer_block_la_SOURCES = test_mifare_classic_create_trailer_block.c
test_mifare_classic_create_trailer_block_la_LIBADD = $(top_srcdir)/libfreefare/libfreefare.la

test_mifare_classic_application_la_SOURCES = test_mifare_classic_application.c
test_mifare_classic_application_la_LIBADD = $(top_srcdir)/libfreefare/libfreefare.la

echo-cutter:
	@echo $(CUTTER)

endif
