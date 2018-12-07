#include <err.h>
#include <stdlib.h>

#include <nfc/nfc.h>

#include <freefare.h>

int
main(void)
{
    nfc_device *device = NULL;
    FreefareTag *tags = NULL;
    nfc_connstring devices[8];

    nfc_context *context;
    nfc_init(&context);
    if (context == NULL)
	errx(EXIT_FAILURE, "Unable to init libnfc (malloc)");

    size_t device_count = nfc_list_devices(context, devices, 8);
    if (device_count <= 0)
	errx(EXIT_FAILURE, "No NFC device found.");

    for (size_t d = 0; d < device_count; d++) {
	device = nfc_open(context, devices[d]);
	if (!device) {
	    errx(EXIT_FAILURE, "nfc_open() failed.");
	}

	tags = freefare_get_tags(device);
	if (!tags) {
	    nfc_close(device);
	    errx(EXIT_FAILURE, "Error listing FeliCa tag.");
	}

	for (int i = 0; tags[i]; i++) {
	    if (FELICA != freefare_get_tag_type(tags[i]))
		continue;

	    char *uid = freefare_get_tag_uid(tags[i]);
	    printf("Dumping %s tag %s\n", freefare_get_tag_friendly_name(tags[i]), uid);
	    free(uid);
	    printf("Number\tName\tData\n");

	    for (int block = 0x00; block < 0x0f; block++) {
		uint8_t buffer[16];

		if (felica_read(tags[i], FELICA_SC_RO, block, buffer, sizeof(buffer)) < 0)
		    errx(EXIT_FAILURE, "Error reading block %d", block);

		if (block < 0x0e)
		    printf("0x%02x\tS_PAD%d\t", block, block);
		else
		    printf("0x%02x\tREG\t", block);
		for (int j = 0; j < 16; j++) {
		    printf("%02x ", buffer[j]);
		}
		printf("\n");
	    }

	    char *block_names[] = {
		"RC", "MAC", "ID", "D_ID", "SER_C", "SYS_C", "CKV", "CK", "MC",
	    };
	    int valid_bytes[] = {
		16, 8, 16, 16, 2, 2, 2, 16, 5
	    };
	    for (int block = 0x80; block < 0x89; block++) {
		uint8_t buffer[16];

		if (felica_read(tags[i], FELICA_SC_RO, block, buffer, sizeof(buffer)) < 0)
		    errx(EXIT_FAILURE, "Error reading block %d", block);

		printf("0x%02x\t%s\t", block, block_names[block - 0x80]);
		for (int j = 0; j < valid_bytes[block - 0x80]; j++) {
		    printf("%02x ", buffer[j]);
		}
		printf("\n");
	    }
	}

	freefare_free_tags(tags);
	nfc_close(device);
    }

    exit(EXIT_SUCCESS);
}
