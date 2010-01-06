#include <stdlib.h>
#include <string.h>
#include <err.h>

#include <nfc/nfc.h>

#include <mifare_common.h>
#include <mifare_classic.h>

#define DEBUG 1

// Useful macros
#ifdef DEBUG
//   #define DBG(x, args...) printf("DBG %s:%d: " x "\n", __FILE__, __LINE__,## args )
  #define DBG(x, ...) fprintf(stderr, "DBG %s:%d: " x "\n", __FILE__, __LINE__, ## __VA_ARGS__ )
#else
  #define DBG(...) {}
#endif

static nfc_device_t *device = NULL;
static MifareClassicTag *tags = NULL;

int
mifare_classic_setup (MifareClassicTag *tag)
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
mifare_classic_teardown (MifareClassicTag tag)
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

void 
print_block(MifareClassicBlock *data)
{
    for(size_t n=0;n<sizeof(MifareClassicBlock);n++) {
        printf("0x%02x ", (*data)[n]);
    }
}

#define block(s,b) ((s * 4) + b)
bool 
sector_is_empty(MifareClassicTag tag, MifareSectorNumber sector)
{
    MifareClassicKey default_key = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    if( 0 != mifare_classic_authenticate(tag, block(sector, 0), default_key, MFC_KEY_A) ) {
        mifare_classic_connect(tag);
        DBG("%s", "Unable to authenticate using default key A.");
        return false;
    }

    MifareClassicBlock default_block = {
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
        0x00, 0x00, 0x00, 0x00, 
    };
    MifareClassicBlock block;
    if( 0 != mifare_classic_read(tag, block(sector, 1), &block) ) {
        DBG("Unable to read block %d of sector %d (%02x).", 1, sector, block(sector, 1));
        return false;
    }

    if( 0 != memcmp( &block, &default_block, sizeof(MifareClassicBlock))) {
        DBG("Block %d of sector %d (%02x) doesn't match with default data.", 1, sector, block(sector, 1));
        return false;
    }

    if( 0 != mifare_classic_read(tag, block(sector, 2), &block) ) {
        DBG("Unable to read block %d of sector %d (%02x).", 2, sector, block(sector, 2));
        return false;
    }

    if( 0 != memcmp( &block, &default_block, sizeof(MifareClassicBlock))) {
        DBG("Block %d of sector %d (%02x) doesn't match with default data.", 2, sector, block(sector, 2));
        return false;
    }

    if( 0 != mifare_classic_read(tag, block(sector, 3), &block) ) {
        DBG("Unable to read block %d of sector %d (%02x).", 3, sector, block(sector, 3));
        return false;
    }

    MifareClassicBlock default_trailer_block = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* Key A could not be read */
        0xff, 0x07, 0x80, /* Default access bits */
        0x69, /* Default GPB */
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, /* Default Key B */
    };
    if( 0 != memcmp( &block, &default_trailer_block, sizeof(MifareClassicBlock))) {
        DBG("Block %d of sector %d (%02x) doesn't match with default data.", 3, sector, block(sector, 3));
        printf("attemped data = "); print_block(&default_trailer_block); printf("\n");
        printf("tag data = "); print_block(&block); printf("\n");
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    MifareClassicTag tag;
    if( 0 == mifare_classic_setup(&tag) ) {
        for(MifareSectorNumber s = 0; s < 16; s++) {
            printf("Sector %d is %s empty.\n", s, sector_is_empty(tag, s) ? "" : "_not_");
        }

#if 0
    MifareClassicKey key_b = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
/*
    if( 0 != mifare_classic_authenticate(tag, 0x04, key_b, MFC_KEY_B) ) {
       errx(1, "Unable to authenticate.");
    }
    mifare_classic_format_sector(tag, 0x04);
    if( 0 != mifare_classic_authenticate(tag, 0x08, key_b, MFC_KEY_B) ) {
       errx(1, "Unable to authenticate.");
    }
    mifare_classic_format_sector(tag, 0x08);
*/
    if( 0 != mifare_classic_authenticate(tag, 0x08 + 4, key_b, MFC_KEY_B) ) {
       errx(1, "Unable to authenticate.");
    }
    mifare_classic_format_sector(tag, 0x08 + 4);

/*
    if( 0 != mifare_classic_authenticate(tag, 0x00, key_b, MFC_KEY_B) ) {
       errx(1, "Unable to authenticate.");
    }

    if( 0 != mifare_classic_write(tag, 0x01, empty) )
      errx(1, "Unable to write on block @0x01");
    if( 0 != mifare_classic_write(tag, 0x02, empty) )
      errx(1, "Unable to write on block @0x02");

    if( 0 != mifare_classic_write(tag, 0x03, trailer) )
      errx(1, "Unable to write trailer block");
*/
#endif

    mifare_classic_teardown(tag);
    exit(EXIT_SUCCESS);
  } else {
    errx(1, "Unable to connect to a MIFARE Classic tag.");
  }
}

