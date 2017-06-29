#include <err.h>
#include <stdlib.h>

#include <nfc/nfc.h>

#include <freefare.h>


int
main(int argc, char *argv[])
{
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    if (argc > 1)
	errx(EXIT_FAILURE, "usage: %s", argv[0]);

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
	    switch (freefare_get_tag_type(tags[i])) {
	    case NTAG_21x:
		break;
	    default:
		continue;
	    }

	    char *tag_uid = freefare_get_tag_uid(tags[i]);
	    printf("Tag with UID %s is a %s\n", tag_uid, freefare_get_tag_friendly_name(tags[i]));
	    FreefareTag tag = tags[i];
	    int res;
	    if (ntag21x_connect(tag) < 0)
		errx(EXIT_FAILURE, "Error connecting to tag.");

	    uint8_t pwd[4] = {0xff, 0xff, 0xff, 0xff};
	    uint8_t pack[2] = {0xaa, 0xaa};
	    uint8_t pack_old[2] = {0x00, 0x00};

	    NTAG21xKey key;
	    NTAG21xKey key_old;
	    key = ntag21x_key_new(pwd, pack); // Creating key
	    key_old = ntag21x_key_new(pwd, pack_old); // Creating key

	    uint8_t auth0 = 0x00; // Buffer for auth0 byte

	    switch (true) {
	    case true:
		/*
		   Get information about tag
		   MUST do, because here we are recognizing tag subtype (NTAG213,NTAG215,NTAG216), and gathering all parameters
		   */
		res = ntag21x_get_info(tag);
		if (res < 0) {
		    printf("Error getting info from tag\n");
		    break;
		}
		// Authenticate with tag
		res = ntag21x_authenticate(tag, key);
		if (res < 0) {
		    printf("Error getting info from tag\n");
		    break;
		}
		// Get auth byte from tag
		res = ntag21x_get_auth(tag, &auth0);
		if (res < 0) {
		    printf("Error getting auth0 byte from tag\n");
		    break;
		}
		printf("Old auth0: %#02x\n", auth0);
		// Set old key
		res = ntag21x_set_key(tag, key_old);
		if (res < 0) {
		    printf("Error setting key tag\n");
		    break;
		}
		// Disable password protection (when auth0 byte > last page)
		res = ntag21x_set_auth(tag, 0xff);
		if (res < 0) {
		    printf("Error setting auth0 byte \n");
		    break;
		}
		// Disable read & write pwd protection -> (default: write only protection)
		res = ntag21x_access_disable(tag, NTAG_PROT);
		if (res < 0) {
		    printf("Error setting access byte \n");
		    break;
		}
		// Get auth byte from tag
		res = ntag21x_get_auth(tag, &auth0);
		if (res < 0) {
		    printf("Error getting auth0 byte from tag\n");
		    break;
		}
		printf("New auth0: %#02x\n", auth0);
	    }

	    ntag21x_disconnect(tag);
	    ntag21x_key_free(key); // Delete key
	    ntag21x_key_free(key_old); // Delete key
	    free(tag_uid);
	}
	freefare_free_tags(tags);
	nfc_close(device);
    }
    nfc_exit(context);
    exit(error);
}
