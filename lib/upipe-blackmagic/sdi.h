#include <inttypes.h>

#include <libzvbi.h>

#define CC_LINE 9
#define AFD_LINE 11
#define OP47_LINE1 12
#define OP47_LINE2 (OP47_LINE1+563)

#define PAL_FIELD_OFFSET 313

#define ANC_START_LEN   6
#define DC_POS          5
#define OP47_INITIAL_WORDS 4
#define OP47_STRUCT_A_LEN 5
#define OP47_STRUCT_B_OFFSET (ANC_START_LEN+OP47_INITIAL_WORDS+OP47_STRUCT_A_LEN)

#define VANC_WIDTH 1920

void sdi_calc_parity_checksum(uint16_t *buf);

void sdi_clear_vbi(uint8_t *dst, int w);

void sdi_clear_vanc(uint16_t *dst);

void sdi_write_cdp(const uint8_t *src, size_t src_size,
        uint16_t *dst, uint16_t *ctr, uint8_t fps);

void sdi_encode_v210_sd(uint32_t *dst, uint8_t *src, int width);
void sdi_encode_v210(uint32_t *dst, uint16_t *src, int width);

int sdi_encode_ttx_sd(uint8_t *buf, const uint8_t *pic_data, vbi_sampling_par *sp);
void sdi_encode_ttx(uint16_t *buf, int packets, const uint8_t **packet, uint16_t *ctr);
