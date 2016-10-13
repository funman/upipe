#include <stdbool.h>
#include <string.h>

#include "sdi.h"

static const bool parity_tab[256] =
{
#   define P2(n) n, n^1, n^1, n
#   define P4(n) P2(n), P2(n^1), P2(n^1), P2(n)
#   define P6(n) P4(n), P4(n^1), P4(n^1), P4(n)
    P6(0), P6(1), P6(1), P6(0)
};

void sdi_calc_parity_checksum(uint16_t *buf, uint16_t dc)
{
    uint16_t checksum = 0;

    /* +3 = did + sdid + dc itself */
    for (uint16_t i = 0; i < dc+3; i++) {
        uint8_t parity = parity_tab[buf[3+i] & 0xff];
        buf[3+i] |= (!parity << 9) | (parity << 8);

        checksum += buf[3+i] & 0x1ff;
    }

    checksum &= 0x1ff;
    checksum |= (!(checksum >> 8)) << 9;

    buf[ANC_START_LEN+dc] = checksum;
}

void sdi_clear_vbi(uint8_t *dst, int w)
{
	memset(&dst[0], 0x10, w);
	memset(&dst[w], 0x80, w);
}

void sdi_clear_vanc(uint16_t *dst)
{
    for (int i = 0; i < VANC_WIDTH; i++)
        dst[i] = 0x40;

    dst += VANC_WIDTH;

    for (int i = 0; i < VANC_WIDTH; i++)
        dst[i] = 0x200;
}

uint16_t *sdi_start_anc(uint16_t *dst, uint16_t did, uint16_t sdid)
{
    /* ADF */
    dst[0] = 0x000;
    dst[1] = 0x3ff;
    dst[2] = 0x3ff;
    /* DID */
    dst[3] = did;
    /* SDID */
    dst[4] = sdid;
    /* DC */
    dst[5] = 0;

    return &dst[5];
}
