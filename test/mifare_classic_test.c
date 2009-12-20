#include "test.h"

static nfc_device_t *device = NULL;
static MifareClassicTag *tags = NULL;

int
mifare_classic_test_setup (MifareClassicTag *tag)
{
    int res = 0;

    *tag = NULL;

    device = nfc_connect (NULL);
    if (!device)
	res = -1;

    if (0 == res) {
	tags = mifare_classic_get_tags (device);
	if (!tags) {
	    nfc_disconnect (device);
	    device = NULL;
	    res = -2;
	}
    }

    if (0 == res) {
	if (!tags[0]) {
	    mifare_classic_free_tags (tags);
	    tags = NULL;
	    nfc_disconnect (device);
	    device = NULL;
	    res = -4;
	}
    }

    if (0 == res) {
	*tag = tags[0];

	res = mifare_classic_connect (*tag);
	if (res != 0) {
	    mifare_classic_disconnect (*tag);
	    nfc_disconnect (device);
	    *tag = NULL;
	    device = NULL;
	    res = -3;
	}
    }

    return res;
}

int
mifare_classic_test_teardown (MifareClassicTag tag)
{
    int res;

    if (tag)
	res = mifare_classic_disconnect (tag);

    if (0 == res) {
	if (tags)
	    mifare_classic_free_tags (tags);

	if (device)
	    nfc_disconnect (device);
    }

    return res;
}

int
read_data_block (char *filename, MifareClassicBlock *block)
{
    FILE *f = fopen (filename, "r");
    if (f == NULL)
	return -1;

    char buffer[17];
    fgets(buffer, 17, f);
    memcpy (block, buffer, 16);
    fclose (f);

    return 0;

}
