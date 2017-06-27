#include <cutter.h>

#include <freefare.h>

#include "felica_fixture.h"

void
test_felica_read_without_encryption(void)
{
    uint8_t buffer[64];

    int res = felica_read(tag, FELICA_SC_RO, 0x00, buffer, 16);
    cut_assert_equal_int(16, res);

    uint8_t blocks[] = {
	0x02,
	0x03,
	0x04,
    };

    res = felica_read_ex(tag, FELICA_SC_RO, 3, blocks, buffer, 3 * 16);
    cut_assert_equal_int(3 * 16, res);
}

void
test_felica_write_without_encryption(void)
{
    uint8_t buffer[16] = {
	0x00, 0x01, 0x02, 0x03,
	0x03, 0x04, 0x05, 0x06,
	0x07, 0x08, 0x09, 0x0a,
	0x0b, 0x0c, 0x0d, 0x0e,
    };

    int res = felica_write(tag, FELICA_SC_RW, 0x0a, buffer, sizeof(buffer));

    cut_assert_equal_int(0, res);
}
