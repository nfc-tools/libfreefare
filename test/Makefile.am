# $Id$

INCLUDES = $(CUTTER_CFLAGS) -I$(top_srcdir)/libfreefare
LIBS = $(CUTTER_LIBS)

SUBDIRS = common .

AM_CFLAGS = @LIBNFC_CFLAGS@

if WITH_CUTTER

TESTS = run-test.sh
TESTS_ENVIRONMENT = NO_MAKE=yes CUTTER="$(CUTTER)"

cutter_unit_test_libs = \
			test_mad.la \
			test_mifare_application.la \
			test_mifare_classic.la \
			test_mifare_classic_create_trailer_block.la \
			test_mifare_classic_sector_boundaries.la \
			test_mifare_desfire.la \
			test_mifare_desfire_aes.la \
			test_mifare_desfire_aid.la \
			test_mifare_desfire_des.la \
			test_mifare_desfire_ev1.la \
			test_mifare_desfire_key.la \
			test_mifare_ultralight.la \
			test_tlv.la

if WITH_DEBUG
noinst_LTLIBRARIES = $(cutter_unit_test_libs)
else
check_LTLIBRARIES = $(cutter_unit_test_libs)
endif

AM_LDFLAGS = -module -rpath $(libdir) -avoid-version -no-undefined

test_mad_la_SOURCES = test_mad.c
test_mad_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_application_la_SOURCES = test_mifare_application.c
test_mifare_application_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_la_SOURCES = test_mifare_classic.c \
				 test_mifare_classic_mad.c \
				 mifare_classic_fixture.c \
				 mifare_classic_fixture.h
test_mifare_classic_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_create_trailer_block_la_SOURCES = test_mifare_classic_create_trailer_block.c
test_mifare_classic_create_trailer_block_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_classic_sector_boundaries_la_SOURCES = test_mifare_classic_sector_boundaries.c
test_mifare_classic_sector_boundaries_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_desfire_la_SOURCES = test_mifare_desfire.c \
				 mifare_desfire_fixture.c \
				 mifare_desfire_fixture.h
test_mifare_desfire_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la \
				$(top_builddir)/test/common/libtestcommon.la

test_mifare_desfire_aes_la_SOURCES = test_mifare_desfire_aes.c
test_mifare_desfire_aes_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_desfire_aid_la_SOURCES = test_mifare_desfire_aid.c
test_mifare_desfire_aid_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_desfire_des_la_SOURCES = test_mifare_desfire_des.c
test_mifare_desfire_des_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_desfire_ev1_la_SOURCES = test_mifare_desfire_ev1.c \
				     test_mifare_desfire_ev1_3des.c \
				     test_mifare_desfire_ev1_3k3des.c \
				     test_mifare_desfire_ev1_aes.c \
				     test_mifare_desfire_ev1_iso.c \
				     mifare_desfire_ev1_fixture.c \
				     mifare_desfire_ev1_fixture.h
test_mifare_desfire_ev1_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la \
				    $(top_builddir)/test/common/libtestcommon.la

test_mifare_desfire_key_la_SOURCES = test_mifare_desfire_key.c
test_mifare_desfire_key_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_mifare_ultralight_la_SOURCES = test_mifare_ultralight.c \
				    mifare_ultralight_fixture.c \
				    mifare_ultralight_fixture.h
test_mifare_ultralight_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

test_tlv_la_SOURCES = test_tlv.c
test_tlv_la_LIBADD = $(top_builddir)/libfreefare/libfreefare.la

echo-cutter:
	@echo $(CUTTER)

EXTRA_DIST = run-test.sh
CLEANFILES = *.gcno

endif
