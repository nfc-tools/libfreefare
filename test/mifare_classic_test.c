#include "test.h"

static nfc_device_t *device;
static MifareClassicTag *tags;

int
mifare_classic_test_setup (MifareClassicTag *tag)
{
    int res = 0;

    device = nfc_connect (NULL);
    if (!device)
	res = -1;

    if (0 == res) {
	tags = mifare_classic_get_tags (device);
	if (!tags || !(tags[0])) {
	    nfc_disconnect (device);
	    res = -2;
	}
    }

    if (0 == res) {
	*tag = tags[0];

	res = mifare_classic_connect (*tag);
	if (res != 0) {
	    mifare_classic_disconnect (*tag);
	    nfc_disconnect (device);
	    res = -3;
	}
    }

    return res;
}

int
mifare_classic_test_teardown (MifareClassicTag tag)
{
    int res;

    res = mifare_classic_disconnect (tag);

    if (0 == res) {
	mifare_classic_free_tags (tags);

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
