#if defined(HAVE_CONFIG_H)
    #include "config.h"
#endif

#include <err.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <nfc/nfc.h>

#include <freefare.h>

uint8_t null_key_data[8];

uint8_t new_key_version = 0x00;

MifareDESFireKey old_picc_key;
MifareDESFireKey new_picc_key;

#define NEW_KEY_VERSION new_key_version

struct {
    bool interactive;
} configure_options = {
    .interactive = true
};

static void
usage(char *progname)
{
    fprintf(stderr, "usage: %s [-y]\n", progname);
    fprintf(stderr, "\nOptions:\n");
    fprintf(stderr, "  -y     Do not ask for confirmation\n");
    fprintf(stderr, "  -k     Existing PICC key (Default is all zeros)\n");
    fprintf(stderr, "  -n     New PICC key (Default is all zeros)\n");
    fprintf(stderr, "  -v     New PICC key version (default is zero)\n");
}

#define strnequal(x, y, n)   (strncmp(x, y, n) == 0)

static inline bool
strhasprefix(const char* str, const char* prefix)
{
    return strnequal(str, prefix, strlen(prefix));
}

MifareDESFireKey read_hex_desfire_key(const char* optarg)
{
    uint8_t buffer[24];
    int i;
    uint64_t n;

    bool is_des = true;

    if (strhasprefix(optarg, "DES:")) {
	is_des = true;
	optarg += 4;
    } else if (strhasprefix(optarg, "AES:")) {
	is_des = false;
	optarg += 4;
    }

    size_t len = strlen(optarg);
    size_t div16 = len / 16;

    if (div16 < 1 || div16 > 3 || (len % 16) != 0) {
	fprintf(stderr,"Bad key length\n");
	exit(EXIT_FAILURE);
    }

    if (div16 >= 1) {
	n = strtoull(optarg, NULL, 16);
	for (i = 7; i >= 0; i--) {
	    buffer[i] = (uint8_t) n;
	    n >>= 8;
	}
    }

    if (div16 >= 2) {
	n = strtoull(optarg+8, NULL, 16);
	for (i = 7; i >= 0; i--) {
	    buffer[i+8] = (uint8_t) n;
	    n >>= 8;
	}
    }

    if (div16 == 3) {
	n = strtoull(optarg+16, NULL, 16);
	for (i = 7; i >= 0; i--) {
	    buffer[i+16] = (uint8_t) n;
	    n >>= 8;
	}
    }

    if (is_des && div16 == 1) {
	return mifare_desfire_des_key_new(buffer);
    }
    if (is_des && div16 == 2) {
	return mifare_desfire_3des_key_new(buffer);
    }
    if (is_des && div16 == 3) {
	return mifare_desfire_3k3des_key_new(buffer);
    }
    if (!is_des && div16 == 2) {
	return mifare_desfire_aes_key_new(buffer);
    }
    fprintf(stderr,"Bad key length\n");
    exit(EXIT_FAILURE);
}

int
main(int argc, char *argv[])
{
    int ch;
    int error = EXIT_SUCCESS;
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    bool should_diversify_new = false;

    old_picc_key = mifare_desfire_des_key_new(null_key_data);
    new_picc_key = mifare_desfire_des_key_new(null_key_data);

    while ((ch = getopt(argc, argv, "hyk:n:v:D")) != -1) {
	switch (ch) {
	case 'h':
	    usage(argv[0]);
	    exit(EXIT_SUCCESS);
	    break;
	case 'y':
	    configure_options.interactive = false;
	    break;
	case 'k':
	    mifare_desfire_key_free(old_picc_key);
	    old_picc_key = read_hex_desfire_key(optarg);
	    break;
	case 'n':
	    mifare_desfire_key_free(new_picc_key);
	    new_picc_key = read_hex_desfire_key(optarg);
	    break;
	case 'v':
	    errno = 0;
	    new_key_version = (uint8_t)strtol(optarg, NULL, 0);
	    if (errno != 0) {
		perror("strtol");
		exit(EXIT_FAILURE);
	    }
	    break;
	case 'D':
	    should_diversify_new = true;
	    break;
	default:
	    usage(argv[0]);
	    exit(EXIT_FAILURE);
	}
    }
    // Remaining args, if any, are in argv[optind .. (argc-1)]

    mifare_desfire_key_set_version(new_picc_key, new_key_version);

    MifareKeyDeriver new_deriver = NULL;
    if (should_diversify_new) {
	new_deriver = mifare_key_deriver_new_an10922(new_picc_key, mifare_desfire_key_get_type(new_picc_key), AN10922_FLAG_DEFAULT);
    }

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

	    int res;

	    res = mifare_desfire_connect(tags[i]);
	    if (res < 0) {
		warnx("Can't connect to Mifare DESFire target.");
		error = EXIT_FAILURE;
		break;
	    }

	    printf("Found %s with UID %s. ", freefare_get_tag_friendly_name(tags[i]), tag_uid);
	    bool do_it = true;

	    if (configure_options.interactive) {
		printf("Change PICC key? [yN] ");
		fgets(buffer, BUFSIZ, stdin);
		do_it = ((buffer[0] == 'y') || (buffer[0] == 'Y'));
	    } else {
		printf("\n");
	    }

	    if (do_it) {

		res = mifare_desfire_authenticate(tags[i], 0, old_picc_key);
		if (res < 0) {
		    freefare_perror(tags[i], "mifare_desfire_authenticate");
		    error = EXIT_FAILURE;
		    break;
		}

		res = mifare_desfire_change_key(tags[i], 0, new_picc_key, old_picc_key);
		if (res < 0) {
		    freefare_perror(tags[i], "mifare_desfire_change_key");
		    error = EXIT_FAILURE;
		    break;
		}

	    }

	    mifare_desfire_disconnect(tags[i]);
	    free(tag_uid);
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }

    mifare_desfire_key_free(old_picc_key);
    mifare_desfire_key_free(new_picc_key);

    nfc_exit(context);
    exit(error);
}
