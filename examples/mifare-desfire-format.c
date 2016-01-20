#if defined(HAVE_CONFIG_H)
#  include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t key_data_picc[8] = { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

struct {
    bool interactive;
} format_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf(stderr, "usage: %s [-y] [-K 11223344AABBCCDD]\n", progname);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -y     Do not ask for confirmation (dangerous)\n");
    fprintf(stderr, "  -K     Provide another PICC key than the default one\n");
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;

    while ((ch = getopt(argc, argv, "hyK:")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	case 'y':
	    format_options.interactive = false;
	    break;
	case 'K':
	    if (strlen(optarg) != 16) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	    }
	    uint64_t n = strtoull(optarg, NULL, 16);
	    int i;
	    for (i = 7; i >= 0; i--) {
		key_data_picc[i] = (uint8_t) n;
		n >>= 8;
	    }
	    break;
	default:
	    usage(argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    nfc_connstring devices[8];
    size_t device_count;

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    device_count = nfc_list_devices(context, devices, 8);
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; (!error) && (d < device_count); d++) {
	device = nfc_open(context, devices[d]);
	if (!device) {
	    warnx("nfc_open() failed.");
	    error = EXIT_FAILURE;
	    continue;
	}

	tags = freefare_get_tags(device);
	if (!tags) {
	    nfc_close(device);
	    errx(EXIT_FAILURE, "Error listing Mifare DESFire tags.");
	}

	for (int i = 0; (!error) && tags[i]; i++) {
	    if (MIFARE_DESFIRE != freefare_get_tag_type(tags[i]))
		continue;

	    char *tag_uid = freefare_get_tag_uid(tags[i]);
	    char buffer[BUFSIZ];

	    printf("Found %s with UID %s. ", freefare_get_tag_friendly_name(tags[i]), tag_uid);
	    bool format = true;
	    if (format_options.interactive) {
		printf("Format [yN] ");
		fgets(buffer, BUFSIZ, stdin);
		format = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf("\n");
	    }

	    if (format) {
		int res;

		res = mifare_desfire_connect(tags[i]);
		if (res < 0) {
		    warnx("Can't connect to Mifare DESFire target.");
		    error = EXIT_FAILURE;
		    break;
		}

		MifareDESFireKey key_picc = mifare_desfire_des_key_new_with_version(key_data_picc);
		res = mifare_desfire_authenticate(tags[i], 0, key_picc);
		if (res < 0) {
		    warnx("Can't authenticate on Mifare DESFire target.");
		    error = EXIT_FAILURE;
		    break;
		}
		mifare_desfire_key_free(key_picc);

		// Send Mifare DESFire ChangeKeySetting to change the PICC master key settings into :
		// bit7-bit4 equal to 0000b
		// bit3 equal to 1b, the configuration of the PICC master key MAY be changeable or frozen
		// bit2 equal to 1b, CreateApplication and DeleteApplication commands are allowed without PICC master key authentication
		// bit1 equal to 1b, GetApplicationIDs, and GetKeySettings are allowed without PICC master key authentication
		// bit0 equal to 1b, PICC masterkey MAY be frozen or changeable
		res = mifare_desfire_change_key_settings(tags[i], 0x0F);
		if (res < 0)
		    errx(EXIT_FAILURE, "ChangeKeySettings failed");
		res = mifare_desfire_format_picc(tags[i]);
		if (res < 0) {
		    warn("Can't format PICC.");
		    error = EXIT_FAILURE;
		    break;
		}

		mifare_desfire_disconnect(tags[i]);
	    }

	    free(tag_uid);
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }
    nfc_exit(context);
    exit(error);
} /* main() */

