#include <inttypes.h>

#define CC_LINE 9
#define AFD_LINE 11
#define OP47_LINE1 12
#define OP47_LINE2 (OP47_LINE1+563)

#define PAL_FIELD_OFFSET 313

#define ANC_START_LEN   6
#define OP47_INITIAL_WORDS 4
#define OP47_STRUCT_A_LEN 5
#define OP47_STRUCT_B_OFFSET (ANC_START_LEN+OP47_INITIAL_WORDS+OP47_STRUCT_A_LEN)

#define VANC_WIDTH 1920

void sdi_calc_parity_checksum(uint16_t *buf, uint16_t dc);

void sdi_clear_vbi(uint8_t *dst, int w);

void sdi_clear_vanc(uint16_t *dst);

uint16_t *sdi_start_anc(uint16_t *dst, uint16_t did, uint16_t sdid);

uint16_t sdi_write_cdp(const uint8_t *src, size_t src_size,
        uint16_t *dst, uint16_t *ctr, uint8_t fps);

void sdi_encode_v210(uint32_t *dst, uint16_t *src, int vbi, int width);
