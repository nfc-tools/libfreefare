
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

man_MANS = freefare.3 \
	   mifare_ultralight.3 \
	   mifare_classic.3 \
	   mad.3 \
	   mifare_application.3

linkedman = \
	    freefare.3 freefare_get_tags.3 \
	    freefare.3 freefare_get_tag_type.3 \
	    freefare.3 freefare_get_tag_friendly_name.3 \
	    freefare.3 freefare_free_tags.3 \
	    mifare_ultralight.3 mifare_ultralight_connect.3 \
	    mifare_ultralight.3 mifare_ultralight_disconnect.3 \
	    mifare_ultralight.3 mifare_ultralight_read.3 \
	    mifare_ultralight.3 mifare_ultralight_write.3 \
	    mifare_ultralight.3 mifare_ultralight_get_uid.3 \
	    mifare_classic.3 mifare_classic_connect.3 \
	    mifare_classic.3 mifare_classic_disconnect.3 \
	    mifare_classic.3 mifare_classic_authenticate.3 \
	    mifare_classic.3 mifare_classic_read.3 \
	    mifare_classic.3 mifare_classic_init_value.3 \
	    mifare_classic.3 mifare_classic_read_value.3 \
	    mifare_classic.3 mifare_classic_write.3 \
	    mifare_classic.3 mifare_classic_increment.3 \
	    mifare_classic.3 mifare_classic_decrement.3 \
	    mifare_classic.3 mifare_classic_restore.3 \
	    mifare_classic.3 mifare_classic_transfer.3 \
	    mifare_classic.3 mifare_classic_get_trailer_block_permission.3 \
	    mifare_classic.3 mifare_classic_get_data_block_permission.3 \
	    mifare_classic.3 mifare_classic_format_sector.3 \
	    mifare_classic.3 mifare_classic_get_uid.3 \
	    mifare_classic.3 mifare_classic_trailer_block.3 \
	    mad.3 mad_new.3 \
	    mad.3 mad_read.3 \
	    mad.3 mad_write.3 \
	    mad.3 mad_get_version.3 \
	    mad.3 mad_set_version.3 \
	    mad.3 mad_get_card_publisher_sector.3 \
	    mad.3 mad_set_card_publisher_sector.3 \
	    mad.3 mad_get_aid.3 \
	    mad.3 mad_set_aid.3 \
	    mad.3 mad_free.3 \
	    mifare_application.3 mifare_application_alloc.3 \
	    mifare_application.3 mifare_application_free.3 \
	    mifare_application.3 mifare_application_find.3

install-data-hook:
	(cd $(DESTDIR)$(man3dir); for i in `echo $(linkedman) | xargs -n2 echo | awk '{print $$2}'`; do rm -f $$i; done; echo $(linkedman) | xargs -n2 $(LN_S))

uninstall-hook:
	(cd $(DESTDIR)$(man3dir); for i in `echo $(linkedman) | xargs -n2 echo | awk '{print $$2}'`; do rm -f $$i; done;)

EXTRA_DIST = freefare_internal.h $(man_MANS)
