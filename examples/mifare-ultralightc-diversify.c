#include <err.h>
#include <stdlib.h>
#include <string.h>

#include <nfc/nfc.h>

#include <freefare.h>

static int
swap_keys(FreefareTag tag, MifareDESFireKey new_key, MifareDESFireKey old_key)
{
    int res;
    res = mifare_ultralightc_authenticate(tag, old_key);
    MifareUltralightPage data;

    if (res != 0) {
	mifare_ultralight_disconnect(tag);
	mifare_ultralight_connect(tag);
    }

    return mifare_ultralightc_set_key(tag, new_key);
}

int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    uint8_t key1_3des_data[16] = { 0x49, 0x45, 0x4D, 0x4B, 0x41, 0x45, 0x52, 0x42, 0x21, 0x4E, 0x41, 0x43, 0x55, 0x4F, 0x59, 0x46 };
    MifareDESFireKey master_key = mifare_desfire_3des_key_new(key1_3des_data);
    MifareDESFireKey derived_key = NULL;
    MifareKeyDeriver deriver = mifare_key_deriver_new_an10922(master_key, MIFARE_KEY_2K3DES, AN10922_FLAG_DEFAULT);
    bool undiversify = (argc == 2 && strcmp("--undiversify",argv[1]) == 0);

    if (argc > 2 || (argc == 2 && strcmp("--undiversify",argv[1]) != 0)) {
	errx(EXIT_FAILURE, "usage: %s [--undiversify]", argv[0]);
    }

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices(context, devices, sizeof(devices) / sizeof(*devices));
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found");

    for (size_t d = 0; d < device_count; d++) {
	if (!(device = nfc_open(context, devices[d]))) {
	    warnx("nfc_open() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}

	if (!(tags = freefare_get_tags(device))) {
	    nfc_close(device);
	    errx(EXIT_FAILURE, "Error listing tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    int res;
	    FreefareTag tag = tags[i];
	    char *tag_uid = freefare_get_tag_uid(tag);

	    switch (freefare_get_tag_type(tag)) {
	    case MIFARE_ULTRALIGHT_C:
		if (mifare_ultralight_connect(tag) < 0) {
		    errx(EXIT_FAILURE, "Error connecting to tag %s.", tag_uid);
		}
		break;
	    default:
		continue;
	    }

	    if (mifare_key_deriver_begin(deriver) < 0) {
		errx(EXIT_FAILURE, "Error starting key diversification");
	    }

	    if (mifare_key_deriver_update_uid(deriver, tag) < 0) {
		errx(EXIT_FAILURE, "Error with key diversification");
	    }

	    if ((derived_key = mifare_key_deriver_end(deriver)) == NULL) {
		errx(EXIT_FAILURE, "Error with key diversification");
	    }

	    if (undiversify) {
		res = swap_keys(tag, master_key, derived_key);
	    } else {
		res = swap_keys(tag, derived_key, master_key);
	    }

	    printf("%siversification of tag with UID %s %s.\n", undiversify?"Und":"D", tag_uid, res?"FAILED":"succeded");

	    mifare_desfire_key_free(derived_key);
	    mifare_ultralight_disconnect(tag);
	    free(tag_uid);
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }

    mifare_desfire_key_free(master_key);
    mifare_key_deriver_free(deriver);
    nfc_exit(context);
    exit(error);
}
