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

	    MadAid aid = {
		.function_cluster_code = 0,
		.application_code = 0
	    };

	    res = mad_get_aid (mad, 3, &aid);
	    assertEqualInt (res, 0);
	    assertEqualInt (aid.function_cluster_code, 0);
	    assertEqualInt (aid.application_code, 0);

	    aid.function_cluster_code = 0xc0;
	    aid.application_code = 0x42;
	    res = mad_set_aid (mad, 3, aid);
	    assertEqualInt (res, 0);

	    res = mad_get_aid (mad, 3, &aid);
	    assertEqualInt (res, 0);
	    assertEqualInt (aid.function_cluster_code, 0xc0);
	    assertEqualInt (aid.application_code, 0x42);

	    mad_free (mad);
	}

    } while (0);
}

