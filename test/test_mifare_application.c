#include "test.h"

DEFINE_TEST(test_mifare_application)
{
    do {

	/* Card publisher part */

	MadAid aid = { 0x22, 0x42 };
	Mad mad = mad_new (2);
	assert (NULL != mad);

	MifareSectorNumber *s_alloc = mifare_application_alloc (mad, aid, 3);
	assert (NULL != s_alloc);

	MifareSectorNumber *s_found = mifare_application_find (mad, aid);
	assert (NULL != s_found);

	for (int i = 0; i < 3; i++) {
	    assertEqualInt (s_alloc[i], s_found[i]);
	}

	assertEqualInt (0, s_alloc[3]);
	assertEqualInt (0, s_found[3]);

	mifare_application_free (mad, aid);

	free (s_alloc);
	free (s_found);

	s_found = mifare_application_find (mad, aid);
	assert (s_found == NULL);

	mad_free (mad);

    } while (0);
}
