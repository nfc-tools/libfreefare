#include <cutter.h>

#include <freefare.h>

void
test_mifare_application(void)
{
    /* Card publisher part */

    MadAid aid = { 0x22, 0x42 };
    Mad mad = mad_new(2);

    int i;

    cut_assert_not_null(mad, cut_message("mad_new() failed"));

    MifareClassicSectorNumber *s_alloc = mifare_application_alloc(mad, aid, 3 * 3 * 16);
    cut_assert_not_null(s_alloc, cut_message("mifare_application_alloc() failed"));

    MifareClassicSectorNumber *s_found = mifare_application_find(mad, aid);
    cut_assert_not_null(s_found, cut_message("mifare_application_alloc() failed"));

    for (i = 0; s_alloc[i]; i++) {
	cut_assert_equal_int(s_alloc[i], s_found[i], cut_message("Allocated and found blocks don't match at position %d", i));
    }

    cut_assert_equal_int(0, s_alloc[i], cut_message("Invalid size"));
    cut_assert_equal_int(0, s_found[i], cut_message("Invalid size"));

    mifare_application_free(mad, aid);

    free(s_alloc);
    free(s_found);

    s_found = mifare_application_find(mad, aid);
    cut_assert_null(s_found, cut_message("mifare_application_free() failed"));

    s_alloc = mifare_application_alloc(mad, aid, 15 * 16 + 1 * 16 + 1);
    cut_assert_not_null(s_alloc, cut_message("mifare_application_alloc() failed"));

    s_found = mifare_application_find(mad, aid);
    cut_assert_not_null(s_found, cut_message("mifare_application_alloc() failed"));



    for (i = 0; s_alloc[i]; i++) {
	cut_assert_equal_int(s_alloc[i], s_found[i], cut_message("Allocated and found blocks don't match at position %d", i));
    }

    cut_assert_equal_int(0, s_alloc[i], cut_message("Invalid size"));
    cut_assert_equal_int(0, s_found[i], cut_message("Invalid size"));


    mifare_application_free(mad, aid);

    free(s_alloc);
    free(s_found);

    s_found = mifare_application_find(mad, aid);
    cut_assert_null(s_found, cut_message("mifare_application_free() failed"));

    mad_free(mad);
}
