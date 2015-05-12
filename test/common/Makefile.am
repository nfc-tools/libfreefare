AM_CPPFLAGS = $(CUTTER_CFLAGS) -I$(top_srcdir)/libfreefare
AM_CFLAGS = @LIBNFC_CFLAGS@

if WITH_CUTTER

cutter_unit_test_libs = \
			libtestcommon.la

if WITH_DEBUG
noinst_LTLIBRARIES = $(cutter_unit_test_libs)
else
check_LTLIBRARIES = $(cutter_unit_test_libs)
endif

libtestcommon_la_SOURCES = mifare_desfire_auto_authenticate.c \
			   mifare_desfire_auto_authenticate.h

endif
