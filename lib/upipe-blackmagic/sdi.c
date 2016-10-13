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

void sdi_calc_parity_checksum(uint16_t *buf)
{
    uint16_t checksum = 0;
    uint16_t dc = buf[DC_POS];

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

void sdi_start_anc(uint16_t *dst, uint16_t did, uint16_t sdid)
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
}

void sdi_write_cdp(const uint8_t *src, size_t src_size,
        uint16_t *dst, uint16_t *ctr, uint8_t fps)
{
    const uint8_t cnt = 9 + src_size + 4;
    const uint16_t hdr_sequence_cntr = (*ctr)++;

    dst[0] = 0x96;
    dst[1] = 0x69;
    dst[2] = cnt;
    dst[3] = (fps << 4) | 0xf; // cdp_frame_rate | Reserved
    dst[4] = (1 << 6) | (1 << 1) | 1; // ccdata_present | caption_service_active | Reserved
    dst[5] = hdr_sequence_cntr >> 8;
    dst[6] = hdr_sequence_cntr & 0xff;
    dst[7] = 0x72;
    dst[8] = (0x7 << 5) | (src_size / 3);

    for (int i = 0; i < src_size; i++)
        dst[9 + i] = src[i];

    dst[9 + src_size] = 0x74;
    dst[9 + src_size + 1] = dst[5];
    dst[9 + src_size + 2] = dst[6];

    uint8_t checksum = 0;
    for (int i = 0; i < cnt-1; i++) // don't include checksum
        checksum += dst[i];

    dst[9 + src_size + 3] = checksum ? 256 - checksum : 0;

    dst[-1] = cnt; // DC
}

static inline uint32_t to_le32(uint32_t a)
{
#ifdef UPIPE_WORDS_BIGENDIAN
    return __builtin_bswap32(a);
#else
    return a;
#endif
}

void sdi_encode_v210_sd(uint32_t *dst, uint8_t *src, int width)
{
    uint8_t *y = src;
    uint8_t *u = &y[width];

#define WRITE_PIXELS8(a, b, c) \
    *dst++ = to_le32((*(a) << 2) | (*(b) << 12) | (*(c) << 22))

    for (int w = 0; w < width; w += 6) {
        WRITE_PIXELS8(u, y, u+1);
        y += 1;
        u += 2;
        WRITE_PIXELS8(y, u, y+1);
        y += 2;
        u += 1;
        WRITE_PIXELS8(u, y, u+1);
        y += 1;
        u += 2;
        WRITE_PIXELS8(y, u, y+1);
        y += 2;
        u += 1;
    }
}

void sdi_encode_v210(uint32_t *dst, uint16_t *src, int width)
{
    /* 1280 isn't mod-6 so long vanc packets will be truncated */
    uint16_t *y = src;
    uint16_t *u = &y[width];

    /* don't clip the v210 anc data */
#define WRITE_PIXELS(a, b, c)           \
    *dst++ = to_le32(*(a) | (*(b) << 10) | (*(c) << 20))

    for (int w = 0; w < width; w += 6) {
        WRITE_PIXELS(u, y, u+1);
        y += 1;
        u += 2;
        WRITE_PIXELS(y, u, y+1);
        y += 2;
        u += 1;
        WRITE_PIXELS(u, y, u+1);
        y += 1;
        u += 2;
        WRITE_PIXELS(y, u, y+1);
        y += 2;
        u += 1;
    }
}
