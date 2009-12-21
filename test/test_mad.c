#include "test.h"

DEFINE_TEST(mad)
{
    int res;

    do {
	Mad mad = mad_new (1);
	assert (mad != NULL);

	if (mad) {
	    assertEqualInt (mad_get_version (mad), 1);
	    mad_set_version (mad, 2);
	    assertEqualInt (mad_get_version (mad), 2);

	    assertEqualInt (0, mad_get_card_publisher_sector (mad));

	    res = mad_set_card_publisher_sector (mad, 13);
	    assertEqualInt (res, 0);
	    assertEqualInt (13, mad_get_card_publisher_sector (mad));

	    res = mad_set_card_publisher_sector (mad, 0xff);
	    assertEqualInt (res, -1);
	    assertEqualInt (13, mad_get_card_publisher_sector (mad));

	    uint8_t fcc, ac;
	    res = mad_get_aid (mad, 3, &fcc, &ac);
	    assertEqualInt (res, 0);
	    assertEqualInt (fcc, 0);
	    assertEqualInt (ac, 0);

	    res = mad_set_aid (mad, 3, 0xc0, 0x42);
	    assertEqualInt (res, 0);

	    res = mad_get_aid (mad, 3, &fcc, &ac);
	    assertEqualInt (res, 0);
	    assertEqualInt (fcc, 0xc0);
	    assertEqualInt (ac, 0x42);

	    mad_free (mad);
	}

    } while (0);
}

