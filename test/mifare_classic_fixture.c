#include <cutter.h>
#include <freefare.h>

static nfc_device_t *device = NULL;
static MifareClassicTag *tags = NULL;
MifareClassicTag tag = NULL;

void
setup ()
{
    int res;

    device = nfc_connect (NULL);
    cut_assert_not_null (device, "No device found");

    tags = mifare_classic_get_tags (device);
    cut_assert_not_null (tags ,"Error enumerating NFC tags");

    cut_assert_not_null (tags[0], "No MIFARE CLassic tag on NFC device");

    tag = tags[0];

    res = mifare_classic_connect (tag);
    cut_assert_equal_int (0, res);
}

void
teardown ()
{
    if (tag)
	mifare_classic_disconnect (tag);

    if (tags)
	mifare_classic_free_tags (tags);

    if (device)
	nfc_disconnect (device);
}

