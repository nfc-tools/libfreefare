#include "test.h"

DEFINE_TEST(access_bit_read_data_block)
{
    int res;
    MifareClassicTag tag;

    do {
      res = mifare_classic_test_setup (&tag);
      assertEqualInt (res, 0);

      MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
      res = mifare_classic_authenticate (tag, 0x04, k, MFC_KEY_A);
      assertEqualInt (res, 0);

      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_R, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_R, MFC_KEY_B) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_W, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_W, MFC_KEY_B) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_D, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_D, MFC_KEY_B) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_I, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_data_block_permission(tag, 0x04, MCAB_I, MFC_KEY_B) );

      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYA, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYA, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYA, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYA, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_ACCESS_BITS, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_ACCESS_BITS, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYB, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_READ_KEYB, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYB, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_trailer_block_permission(tag, 0x04, MCAB_WRITE_KEYB, MFC_KEY_B) );

    } while (0);

    mifare_classic_test_teardown (tag);
}

DEFINE_TEST(access_bit_read_trailer_block)
{
    int res;
    MifareClassicTag tag;

    do {
      res = mifare_classic_test_setup (&tag);
      assertEqualInt (res, 0);

      MifareClassicKey k = { 0xd3, 0xf7, 0xd3, 0xf7, 0xd3, 0xf7 };
      res = mifare_classic_authenticate (tag, 0x07, k, MFC_KEY_A);
      assertEqualInt (res, 0);

      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_R, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_R, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_W, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_W, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_D, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_D, MFC_KEY_B) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_I, MFC_KEY_A) );
      assertEqualInt (-1, mifare_classic_get_data_block_permission(tag, 0x07, MCAB_I, MFC_KEY_B) );

      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYA, MFC_KEY_A) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYA, MFC_KEY_B) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYA, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYA, MFC_KEY_B) );
      assertEqualInt (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_ACCESS_BITS, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_ACCESS_BITS, MFC_KEY_B) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_ACCESS_BITS, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_ACCESS_BITS, MFC_KEY_B) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYB, MFC_KEY_A) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_READ_KEYB, MFC_KEY_B) );
      assertEqualInt (0, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYB, MFC_KEY_A) );
      assertEqualInt (1, mifare_classic_get_trailer_block_permission(tag, 0x07, MCAB_WRITE_KEYB, MFC_KEY_B) );

    } while (0);
    mifare_classic_test_teardown (tag);
}
