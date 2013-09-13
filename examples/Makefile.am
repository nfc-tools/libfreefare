# $Id$

AM_CFLAGS = -I. -I$(top_srcdir)/libfreefare @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

bin_PROGRAMS = mifare-classic-format \
	       mifare-classic-write-ndef \
	       mifare-classic-read-ndef \
	       mifare-desfire-access \
	       mifare-desfire-create-ndef \
	       mifare-desfire-ev1-configure-ats \
	       mifare-desfire-ev1-configure-default-key \
	       mifare-desfire-ev1-configure-random-uid \
	       mifare-desfire-format \
	       mifare-desfire-info \
	       mifare-desfire-info-pcsc \
	       mifare-desfire-read-ndef \
	       mifare-desfire-write-ndef \
	       mifare-ultralight-info \
	       mifare-ultralight-info-pcsc

mifare_classic_format_SOURCES = mifare-classic-format.c
mifare_classic_format_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_classic_read_ndef_SOURCES = mifare-classic-read-ndef.c
mifare_classic_read_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_classic_write_ndef_SOURCES = mifare-classic-write-ndef.c
mifare_classic_write_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_access_SOURCES = mifare-desfire-access.c
mifare_desfire_access_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_create_ndef_SOURCES = mifare-desfire-create-ndef.c
mifare_desfire_create_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_ev1_configure_ats_SOURCES = mifare-desfire-ev1-configure-ats.c
mifare_desfire_ev1_configure_ats_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_ev1_configure_default_key_SOURCES = mifare-desfire-ev1-configure-default-key.c
mifare_desfire_ev1_configure_default_key_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_ev1_configure_random_uid_SOURCES = mifare-desfire-ev1-configure-random-uid.c
mifare_desfire_ev1_configure_random_uid_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_format_SOURCES = mifare-desfire-format.c
mifare_desfire_format_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_info_SOURCES = mifare-desfire-info.c
mifare_desfire_info_LDADD = $(top_builddir)/libfreefare/libfreefare.la -lm

mifare_desfire_info_pcsc_SOURCES = mifare-desfire-info-pcsc.c
mifare_desfire_info_pcsc_LDADD = $(top_builddir)/libfreefare/libfreefare.la -lm

mifare_desfire_read_ndef_SOURCES = mifare-desfire-read-ndef.c
mifare_desfire_read_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_desfire_write_ndef_SOURCES = mifare-desfire-write-ndef.c
mifare_desfire_write_ndef_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_ultralight_info_SOURCES = mifare-ultralight-info.c
mifare_ultralight_info_LDADD = $(top_builddir)/libfreefare/libfreefare.la

mifare_ultralight_info_pcsc_SOURCES = mifare-ultralight-info-pcsc.c
mifare_ultralight_info_pcsc_LDADD = $(top_builddir)/libfreefare/libfreefare.la

CLEANFILES=	*.gcno
