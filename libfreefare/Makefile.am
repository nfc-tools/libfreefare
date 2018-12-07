AM_CFLAGS = @LIBNFC_CFLAGS@
AM_LDFLAGS = @LIBNFC_LIBS@

lib_LTLIBRARIES = libfreefare.la

libfreefare_la_SOURCES = felica.c \
			 freefare.c \
			 mifare_classic.c \
			 mifare_ultralight.c \
			 mifare_desfire.c \
			 mifare_desfire_aid.c \
			 mifare_desfire_crypto.c \
			 mifare_desfire_error.c \
			 mifare_desfire_key.c \
			 mifare_key_deriver.c \
			 mad.c \
			 mifare_application.c \
			 ntag21x.c \
			 ntag21x_error.c \
			 tlv.c
libfreefare_la_LIBADD =

if WITH_DEBUG
  AM_CFLAGS += -DWITH_DEBUG
if HAS_LIBUTIL
    libfreefare_la_LIBADD += -lutil
else # HAS_LIBUTIL
    libfreefare_la_LIBADD += $(top_builddir)/contrib/libutil/libutil.la
    AM_CFLAGS += -I$(top_builddir)/contrib/libutil/
endif # !HAS_LIBUTIL
endif # WITH_DEBUG

libfreefare_la_HEADERS = freefare.h
libfreefare_ladir = $(includedir)

man_MANS = freefare.3 \
	   freefare_error.3 \
	   mad.3 \
	   mifare_application.3 \
	   mifare_classic.3 \
	   mifare_desfire.3 \
	   mifare_desfire_aid.3 \
	   mifare_desfire_key.3 \
	   mifare_key_deriver.3 \
	   mifare_ultralight.3 \
	   ntag21x.3 \
	   tlv.3

linkedman = \
	    freefare.3 freefare_free_tags.3 \
	    freefare.3 freefare_get_tag_friendly_name.3 \
	    freefare.3 freefare_get_tag_type.3 \
	    freefare.3 freefare_get_tag_uid.3 \
	    freefare.3 freefare_get_tags.3 \
	    freefare_error.3 freefare_perror.3 \
	    freefare_error.3 freefare_strerror.3 \
	    freefare_error.3 freefare_strerror_r.3 \
	    freefare_error.3 mifare_desfire_last_pcd_error.3 \
	    freefare_error.3 mifare_desfire_last_picc_error.3 \
	    mad.3 mad_free.3 \
	    mad.3 mad_get_aid.3 \
	    mad.3 mad_get_card_publisher_sector.3 \
	    mad.3 mad_get_version.3 \
	    mad.3 mad_new.3 \
	    mad.3 mad_read.3 \
	    mad.3 mad_set_aid.3 \
	    mad.3 mad_set_card_publisher_sector.3 \
	    mad.3 mad_set_version.3 \
	    mad.3 mad_write.3 \
	    mifare_application.3 mifare_application_alloc.3 \
	    mifare_application.3 mifare_application_find.3 \
	    mifare_application.3 mifare_application_free.3 \
	    mifare_application.3 mifare_application_read.3 \
	    mifare_application.3 mifare_application_write.3 \
	    mifare_classic.3 mifare_classic_authenticate.3 \
	    mifare_classic.3 mifare_classic_connect.3 \
	    mifare_classic.3 mifare_classic_decrement.3 \
	    mifare_classic.3 mifare_classic_disconnect.3 \
	    mifare_classic.3 mifare_classic_format_sector.3 \
	    mifare_classic.3 mifare_classic_get_data_block_permission.3 \
	    mifare_classic.3 mifare_classic_get_trailer_block_permission.3 \
	    mifare_classic.3 mifare_classic_get_uid.3 \
	    mifare_classic.3 mifare_classic_increment.3 \
	    mifare_classic.3 mifare_classic_init_value.3 \
	    mifare_classic.3 mifare_classic_read.3 \
	    mifare_classic.3 mifare_classic_read_value.3 \
	    mifare_classic.3 mifare_classic_restore.3 \
	    mifare_classic.3 mifare_classic_trailer_block.3 \
	    mifare_classic.3 mifare_classic_transfer.3 \
	    mifare_classic.3 mifare_classic_write.3 \
	    mifare_desfire.3 mifare_desfire_abort_transaction.3 \
	    mifare_desfire.3 mifare_desfire_authenticate.3 \
	    mifare_desfire.3 mifare_desfire_authenticate_aes.3 \
	    mifare_desfire.3 mifare_desfire_authenticate_iso.3 \
	    mifare_desfire.3 mifare_desfire_change_file_settings.3 \
	    mifare_desfire.3 mifare_desfire_change_key.3 \
	    mifare_desfire.3 mifare_desfire_change_key_settings.3 \
	    mifare_desfire.3 mifare_desfire_clear_record_file.3 \
	    mifare_desfire.3 mifare_desfire_commit_transaction.3 \
	    mifare_desfire.3 mifare_desfire_connect.3 \
	    mifare_desfire.3 mifare_desfire_create_application.3 \
	    mifare_desfire.3 mifare_desfire_create_backup_data_file.3 \
	    mifare_desfire.3 mifare_desfire_create_cyclic_record_file.3 \
	    mifare_desfire.3 mifare_desfire_create_linear_record_file.3 \
	    mifare_desfire.3 mifare_desfire_create_std_data_file.3 \
	    mifare_desfire.3 mifare_desfire_create_value_file.3 \
	    mifare_desfire.3 mifare_desfire_credit.3 \
	    mifare_desfire.3 mifare_desfire_credit_ex.3 \
	    mifare_desfire.3 mifare_desfire_debit.3 \
	    mifare_desfire.3 mifare_desfire_debit_ex.3 \
	    mifare_desfire.3 mifare_desfire_delete_application.3 \
	    mifare_desfire.3 mifare_desfire_delete_file.3 \
	    mifare_desfire.3 mifare_desfire_disconnect.3 \
	    mifare_desfire.3 mifare_desfire_format_picc.3 \
	    mifare_desfire.3 mifare_desfire_free_application_ids.3 \
	    mifare_desfire.3 mifare_desfire_free_mem.3 \
	    mifare_desfire.3 mifare_desfire_get_application_ids.3 \
	    mifare_desfire.3 mifare_desfire_get_card_uid.3 \
	    mifare_desfire.3 mifare_desfire_get_file_ids.3 \
	    mifare_desfire.3 mifare_desfire_get_file_settings.3 \
	    mifare_desfire.3 mifare_desfire_get_key_settings.3 \
	    mifare_desfire.3 mifare_desfire_get_key_version.3 \
	    mifare_desfire.3 mifare_desfire_get_value.3 \
	    mifare_desfire.3 mifare_desfire_get_value_ex.3 \
	    mifare_desfire.3 mifare_desfire_get_version.3 \
	    mifare_desfire.3 mifare_desfire_limited_credit.3 \
	    mifare_desfire.3 mifare_desfire_limited_credit_ex.3 \
	    mifare_desfire.3 mifare_desfire_read_data.3 \
	    mifare_desfire.3 mifare_desfire_read_data_ex.3 \
	    mifare_desfire.3 mifare_desfire_read_records.3 \
	    mifare_desfire.3 mifare_desfire_read_records_ex.3 \
	    mifare_desfire.3 mifare_desfire_select_application.3 \
	    mifare_desfire.3 mifare_desfire_set_ats.3 \
	    mifare_desfire.3 mifare_desfire_set_configuration.3 \
	    mifare_desfire.3 mifare_desfire_set_default_key.3 \
	    mifare_desfire.3 mifare_desfire_write_data.3 \
	    mifare_desfire.3 mifare_desfire_write_data_ex.3 \
	    mifare_desfire.3 mifare_desfire_write_record.3 \
	    mifare_desfire.3 mifare_desfire_write_record_ex.3 \
	    mifare_desfire_aid.3 mifare_desfire_aid_get_aid.3 \
	    mifare_desfire_aid.3 mifare_desfire_aid_new.3 \
	    mifare_desfire_aid.3 mifare_desfire_aid_new_with_mad_aid.3 \
	    mifare_desfire_key.3 mifare_desfire_3des_key_new.3 \
	    mifare_desfire_key.3 mifare_desfire_3des_key_new_with_version.3 \
	    mifare_desfire_key.3 mifare_desfire_3k3des_key_new.3 \
	    mifare_desfire_key.3 mifare_desfire_3k3des_key_new_with_version.3 \
	    mifare_desfire_key.3 mifare_desfire_aes_key_new.3 \
	    mifare_desfire_key.3 mifare_desfire_aes_key_new_with_version.3 \
	    mifare_desfire_key.3 mifare_desfire_des_key_new.3 \
	    mifare_desfire_key.3 mifare_desfire_des_key_new_with_version.3 \
	    mifare_desfire_key.3 mifare_desfire_key_free.3 \
	    mifare_desfire_key.3 mifare_desfire_key_get_version.3 \
	    mifare_desfire_key.3 mifare_desfire_key_set_version.3 \
	    mifare_ultralight.3 mifare_ultralight_connect.3 \
	    mifare_ultralight.3 mifare_ultralight_disconnect.3 \
	    mifare_ultralight.3 mifare_ultralight_get_uid.3 \
	    mifare_ultralight.3 mifare_ultralight_read.3 \
	    mifare_ultralight.3 mifare_ultralight_write.3 \
	    mifare_ultralight.3 mifare_ultralightc_authenticate.3 \
	    tlv.3 tlv_decode.3 \
	    tlv.3 tlv_encode.3

install-data-hook:
	(cd $(DESTDIR)$(man3dir); for i in `echo $(linkedman) | xargs -n2 echo | awk '{print $$2}'`; do rm -f $$i; done; echo $(linkedman) | xargs -n2 $(LN_S))

uninstall-hook:
	(cd $(DESTDIR)$(man3dir); for i in `echo $(linkedman) | xargs -n2 echo | awk '{print $$2}'`; do rm -f $$i; done;)

EXTRA_DIST = freefare_internal.h $(man_MANS)
CLEANFILES = *.gcno
