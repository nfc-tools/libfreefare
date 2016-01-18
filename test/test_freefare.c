#include <cutter.h>

#include <freefare.h>
#include "freefare_internal.h"

void
test_is_mifare_ultralight (void)
{
    FreefareTag tag;
    nfc_target target;

    tag = mifare_ultralight_tag_new (NULL, target);
    cut_assert_true (is_mifare_ultralight (tag));
    mifare_ultralight_tag_free (tag);
}

void
test_is_mifare_ultralightc (void)
{
    FreefareTag tag;
    nfc_target target;

    tag = mifare_ultralightc_tag_new (NULL, target);
    cut_assert_true (is_mifare_ultralightc (tag));
    mifare_ultralightc_tag_free (tag);
}
