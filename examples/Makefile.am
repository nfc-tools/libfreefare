AM_CFLAGS = -I. -I$(top_srcdir)/libfreefare @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

bin_PROGRAMS = mifare-classic-format \
	       mifare-classic-write-ndef

mifare_classic_format_SOURCES = mifare-classic-format.c
mifare_classic_format_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la

mifare_classic_write_ndef_SOURCES = mifare-classic-write-ndef.c
mifare_classic_write_ndef_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la
