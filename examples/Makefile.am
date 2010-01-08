AM_CFLAGS = -I. @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

bin_PROGRAMS = mifare-classic-format

mifare_classic_format_SOURCES = mifare-classic-format.c
mifare_classic_format_LDADD = -lnfc $(top_builddir)/libfreefare/libfreefare.la
