#include <freefare.h>
#include <cutter.h>

#include "freefare_internal.h"

void
test_mifare_desfire_aid (void)
{
    /*
     * <-- LSB                                                                       MSB -->
     * | MIFARE DESFire AID Byte 0 | MIFARE DESFire AID Byte 1 | MIFARE DESFire AID Byte 2 |
     * |   Nible 0   |   Nible 1   |   Nible 2   |   Nible 3   |   Nible 4   |   Nible 5   |
     * |     0xF     |                   MIFARE Classic AID                  |  0x0...0xF  |
     *               |          Function-Cluster | Application code          |
     *               <-- MSB                                            LSB-->
     *
     * 0xF21438 -> 0x83412F
     */
    MifareDESFireAID desfire_aid = mifare_desfire_aid_new (0x00f12ab8);
    MadAid mad_aid = {
	.function_cluster_code = 0x12,
	.application_code = 0xab,
    };
    MifareDESFireAID desfire_aid2 = mifare_desfire_aid_new_with_mad_aid (mad_aid, 8);

    cut_assert_equal_memory (desfire_aid->data,3, desfire_aid2->data, 3, cut_message ("wrong aid"));

}
