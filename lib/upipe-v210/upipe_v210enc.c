/*
 * V210 encoder
 *
 * Copyright (C) 2009 Michael Niedermayer <michaelni@gmx.at>
 * Copyright (c) 2009 Baptiste Coudurier <baptiste dot coudurier at gmail dot com>
 * Copyright (c) 2015 Open Broadcast Systems Ltd
 *
 * This file originates from FFmpeg.
 *
 * FFmpeg is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * FFmpeg is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with FFmpeg; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 */

/** @file
 * @short Upipe v210enc module
 */

#include "upipe_v210enc.h"

/** @hidden */
static bool upipe_v210enc_handle(struct upipe *upipe, struct uref *uref,
                             struct upump **upump_p);
/** @hidden */
static int upipe_v210enc_check(struct upipe *upipe, struct uref *flow_format);


UPIPE_HELPER_UPIPE(upipe_v210enc, upipe, UPIPE_V210ENC_SIGNATURE);
UPIPE_HELPER_UREFCOUNT(upipe_v210enc, urefcount, upipe_v210enc_free);
static struct upipe *upipe_v210enc_alloc_void(struct upipe_mgr *mgr,          
                                            struct uprobe *uprobe,          
                                            uint32_t signature,             
                                            va_list args)                   
{                                                                           
    if (signature != UPIPE_VOID_SIGNATURE) {                                
        uprobe_release(uprobe);                                             
        return NULL;                                                        
    }                                                                       
    struct upipe_v210enc *s =                                                   
        (struct upipe_v210enc *)malloc(sizeof(struct upipe_v210enc));               
    if (unlikely(s == NULL)) {                                              
        uprobe_release(uprobe);                                             
        return NULL;                                                        
    }                                                                       
    struct upipe *upipe = upipe_v210enc_to_upipe(s);                          
    upipe_init(upipe, mgr, uprobe);                                         
    return upipe;                                                           
}

static void upipe_v210enc_free_void(struct upipe *upipe)                      
{                                                                           
    struct upipe_v210enc *s = upipe_v210enc_from_upipe(upipe);                    
    upipe_clean(upipe);                                                     
    free(s);                                                                
}


UPIPE_HELPER_OUTPUT(upipe_v210enc, output, flow_def, output_state, request_list)
UPIPE_HELPER_UBUF_MGR(upipe_v210enc, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_v210enc_check,
                      upipe_v210enc_register_output_request,
                      upipe_v210enc_unregister_output_request)
UPIPE_HELPER_INPUT(upipe_v210enc, urefs, nb_urefs, max_urefs, blockers, upipe_v210enc_handle)


#define CLIP(v) av_clip(v, 4, 1019)
#define CLIP8(v) av_clip(v, 1, 254)

#define WRITE_PIXELS(a, b, c)           \
    do {                                \
        val =   CLIP(*a++);             \
        val |= (CLIP(*b++) << 10) |     \
               (CLIP(*c++) << 20);      \
        AV_WL32(dst, val);              \
        dst += 4;                       \
    } while (0)

#define WRITE_PIXELS8(a, b, c)          \
    do {                                \
        val =  (CLIP8(*a++) << 2);       \
        val |= (CLIP8(*b++) << 12) |     \
               (CLIP8(*c++) << 22);      \
        AV_WL32(dst, val);              \
        dst += 4;                       \
    } while (0)

static void v210enc_planar_pack_8_c(const uint8_t *y, const uint8_t *u,
                                 const uint8_t *v, uint8_t *dst, ptrdiff_t width)
{
    uint32_t val;
    int i;

    /* unroll this to match the assembly */
    for( i = 0; i < width-11; i += 12 ){
        WRITE_PIXELS8(u, y, v);
        WRITE_PIXELS8(y, u, y);
        WRITE_PIXELS8(v, y, u);
        WRITE_PIXELS8(y, v, y);
        WRITE_PIXELS8(u, y, v);
        WRITE_PIXELS8(y, u, y);
        WRITE_PIXELS8(v, y, u);
        WRITE_PIXELS8(y, v, y);
    }
}

static void v210enc_planar_pack_10_c(const uint16_t *y, const uint16_t *u,
                                  const uint16_t *v, uint8_t *dst, ptrdiff_t width)
{
    uint32_t val;
    int i;

    for( i = 0; i < width-5; i += 6 ){
        WRITE_PIXELS(u, y, v);
        WRITE_PIXELS(y, u, y);
        WRITE_PIXELS(v, y, u);
        WRITE_PIXELS(y, v, y);
    }
}

/** @internal @This handles data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure describing the picture
 * @param upump_p reference to pump that generated the buffer
 * @return false if the input must be blocked
 */
static bool upipe_v210enc_handle(struct upipe *upipe, struct uref *uref,
                             struct upump **upump_p)
{
    struct upipe_v210enc *upipe_v210enc = upipe_v210enc_from_upipe(upipe);
    const char *def;
    if (unlikely(ubase_check(uref_flow_get_def(uref, &def)))) {
        upipe_v210enc_store_flow_def(upipe, uref);
        upipe_v210enc_require_ubuf_mgr(upipe, uref);
        return true;
    }

    if (upipe_v210enc->flow_def == NULL)
        return false;

    size_t input_hsize, input_vsize;
    if (!ubase_check(uref_pic_size(uref, &input_hsize, &input_vsize, NULL))) {
        upipe_warn(upipe, "invalid buffer received");
        uref_free(uref);
        return true;
    }

    /* map input */
    const uint8_t *input_planes[UPIPE_V210_MAX_PLANES + 1];
    int input_strides[UPIPE_V210_MAX_PLANES + 1];
    int i;
    for (i = 0; i < UPIPE_V210_MAX_PLANES &&
                upipe_v210enc->input_chroma_map[i] != NULL; i++) {
        const uint8_t *data;
        size_t stride;
        if (unlikely(!ubase_check(uref_pic_plane_read(uref,
                                          upipe_v210enc->input_chroma_map[i],
                                          0, 0, -1, -1, &data)) ||
                     !ubase_check(uref_pic_plane_size(uref,
                                          upipe_v210enc->input_chroma_map[i],
                                          &stride, NULL, NULL, NULL)))) {
            upipe_warn(upipe, "invalid buffer received");
            uref_free(uref);
            return true;
        }
        input_planes[i] = data;
        input_strides[i] = stride;
    }
    input_planes[i] = NULL;
    input_strides[i] = 0;

    /* allocate dest ubuf */
    struct ubuf *ubuf = ubuf_pic_alloc(upipe_v210enc->ubuf_mgr,
                                       input_hsize, input_vsize);
    if (unlikely(ubuf == NULL)) {
        for (i = 0; i < UPIPE_V210_MAX_PLANES &&
                    upipe_v210enc->input_chroma_map[i] != NULL; i++)
            uref_pic_plane_unmap(uref, upipe_v210enc->input_chroma_map[i],
                                 0, 0, -1, -1);
        uref_free(uref);
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return true;
    }

    /* map output */
    uint8_t *output_plane;
    size_t output_stride;
    if (unlikely(!ubase_check(ubuf_pic_plane_write(ubuf,
                                       upipe_v210enc->output_chroma_map,
                                       0, 0, -1, -1, &output_plane)) ||
                 !ubase_check(ubuf_pic_plane_size(ubuf,
                                       upipe_v210enc->output_chroma_map,
                                       &output_stride, NULL, NULL, NULL)))) {
        upipe_warn(upipe, "invalid buffer received");
        ubuf_free(ubuf);
        uref_free(uref);
        return true;
    }

    /* Do v210 packing */


    /* unmap pictures */
    for (i = 0; i < UPIPE_V210_MAX_PLANES &&
                upipe_v210enc->input_chroma_map[i] != NULL; i++)
        uref_pic_plane_unmap(uref, upipe_v210enc->input_chroma_map[i],
                             0, 0, -1, -1);

    ubuf_pic_plane_unmap(ubuf, upipe_v210enc->output_chroma_map,
                         0, 0, -1, -1);

    uref_attach_ubuf(uref, ubuf);
    upipe_v210enc_output(upipe, uref, upump_p);
    return true;
}

/** @internal @This receives incoming uref.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure describing the picture
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_v210enc_input(struct upipe *upipe, struct uref *uref,
                            struct upump **upump_p)
{
    if (!upipe_v210enc_check_input(upipe)) {
        upipe_v210enc_hold_input(upipe, uref);
        upipe_v210enc_block_input(upipe, upump_p);
    } else if (!upipe_v210enc_handle(upipe, uref, upump_p)) {
        upipe_v210enc_hold_input(upipe, uref);
        upipe_v210enc_block_input(upipe, upump_p);
        /* Increment upipe refcount to avoid disappearing before all packets
         * have been sent. */
        upipe_use(upipe);
    }
}

/** @internal @This receives a provided ubuf manager.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_v210enc_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_v210enc *upipe_v210enc = upipe_v210enc_from_upipe(upipe);
    if (flow_format != NULL)
        upipe_v210enc_store_flow_def(upipe, flow_format);

    if (upipe_v210enc->flow_def == NULL)
        return UBASE_ERR_NONE;

    bool was_buffered = !upipe_v210enc_check_input(upipe);
    upipe_v210enc_output_input(upipe);
    upipe_v210enc_unblock_input(upipe);
    if (was_buffered && upipe_v210enc_check_input(upipe)) {
        /* All packets have been output, release again the pipe that has been
         * used in @ref upipe_v210enc_input. */
        upipe_release(upipe);
    }
    return UBASE_ERR_NONE;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_v210enc_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;

    UBASE_RETURN(uref_flow_match_def(flow_def, "pic."))

    struct upipe_v210enc *upipe_v210enc = upipe_v210enc_from_upipe(upipe);
    struct uref *flow_def_dup;

    if ((flow_def_dup = uref_dup(flow_def)) == NULL)
        return UBASE_ERR_ALLOC;

    uint8_t macropixel;
    if (!ubase_check(uref_pic_flow_get_macropixel(flow_def, &macropixel)))
        return -1;

#define u ubase_check
    if (!(macropixel == 1 &&
           ((u(uref_pic_flow_check_chroma(flow_def, 1, 1, 1, "y8")) &&
             u(uref_pic_flow_check_chroma(flow_def, 2, 1, 1, "u8")) &&
             u(uref_pic_flow_check_chroma(flow_def, 2, 1, 1, "v8"))) ||
            (u(uref_pic_flow_check_chroma(flow_def, 1, 1, 2, "y10l")) &&
             u(uref_pic_flow_check_chroma(flow_def, 2, 1, 2, "u10l")) &&
             u(uref_pic_flow_check_chroma(flow_def, 2, 1, 2, "v10l")))))) {
        upipe_err(upipe, "incompatible input flow def");
        uref_dump(flow_def, upipe->uprobe);
        return UBASE_ERR_EXTERNAL;
    }

    upipe_v210enc->input_bit_depth = u(uref_pic_flow_check_chroma(flow_def, 1, 1, 1, "y8")) ? 8 : 10;
#undef u

    if (upipe_v210enc->input_bit_depth == 8){
        upipe_v210enc->input_chroma_map[0] = "y8";
        upipe_v210enc->input_chroma_map[1] = "u8";
        upipe_v210enc->input_chroma_map[2] = "v8";
        upipe_v210enc->input_chroma_map[3] = NULL;
    }
    else {
        upipe_v210enc->input_chroma_map[0] = "y10l";
        upipe_v210enc->input_chroma_map[1] = "u10l";
        upipe_v210enc->input_chroma_map[2] = "v10l";
        upipe_v210enc->input_chroma_map[3] = NULL;
    }

    upipe_v210enc->output_chroma_map = "u10y10v10y10u10y10v10y10u10y10v10y10";

    uref_pic_flow_set_align(flow_def_dup, 16);
    uref_pic_flow_set_planes(flow_def_dup, 1);
    uref_pic_flow_set_macropixel(flow_def_dup, 6);
    uref_pic_flow_set_macropixel_size(flow_def_dup, 16, 0);
    uref_pic_flow_set_chroma(flow_def_dup, upipe_v210enc->output_chroma_map, 0);
    
    upipe_input(upipe, flow_def_dup, NULL);
    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on a file source pipe, and
 * checks the status of the pipe afterwards.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_v210enc_control(struct upipe *upipe, int command, va_list args)
{
    switch (command) {
        case UPIPE_REGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            if (request->type == UREQUEST_UBUF_MGR ||
                request->type == UREQUEST_FLOW_FORMAT)
                return upipe_throw_provide_request(upipe, request);
            return upipe_v210enc_alloc_output_proxy(upipe, request);
        }
        case UPIPE_UNREGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            if (request->type == UREQUEST_UBUF_MGR ||
                request->type == UREQUEST_FLOW_FORMAT)
                return UBASE_ERR_NONE;
            return upipe_v210enc_free_output_proxy(upipe, request);
        }

        case UPIPE_GET_OUTPUT: {
            struct upipe **p = va_arg(args, struct upipe **);
            return upipe_v210enc_get_output(upipe, p);
        }
        case UPIPE_SET_OUTPUT: {
            struct upipe *output = va_arg(args, struct upipe *);
            return upipe_v210enc_set_output(upipe, output);
        }
        case UPIPE_GET_FLOW_DEF: {
            struct uref **p = va_arg(args, struct uref **);
            return upipe_v210enc_get_flow_def(upipe, p);
        }
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow = va_arg(args, struct uref *);
            return upipe_v210enc_set_flow_def(upipe, flow);
        }
        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @internal @This allocates a v210enc pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_v210enc_alloc(struct upipe_mgr *mgr,
                                     struct uprobe *uprobe,
                                     uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_v210enc_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

    struct upipe_v210enc *upipe_v210enc = upipe_v210enc_from_upipe(upipe);
    upipe_v210enc->cpu_flags = av_get_cpu_flags();

    upipe_v210enc->pack_line_8  = v210enc_planar_pack_8_c;
    upipe_v210enc->pack_line_10 = v210enc_planar_pack_10_c;

    upipe_v210enc_init_urefcount(upipe);
    upipe_v210enc_init_ubuf_mgr(upipe);
    upipe_v210enc_init_output(upipe);
    upipe_v210enc_init_input(upipe);

    upipe_throw_ready(upipe);
    return upipe;
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_v210enc_free(struct upipe *upipe)
{
    struct upipe_v210enc *upipe_v210enc = upipe_v210enc_from_upipe(upipe);

    upipe_throw_dead(upipe);
    upipe_v210enc_clean_input(upipe);
    upipe_v210enc_clean_output(upipe);
    upipe_v210enc_clean_ubuf_mgr(upipe);
    upipe_v210enc_clean_urefcount(upipe);
    upipe_v210enc_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_v210enc_mgr = {
    .refcount = NULL,
    .signature = UPIPE_V210ENC_SIGNATURE,

    .upipe_alloc = upipe_v210enc_alloc,
    .upipe_input = upipe_v210enc_input,
    .upipe_control = upipe_v210enc_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for v210enc pipes
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_v210enc_mgr_alloc(void)
{
    return &upipe_v210enc_mgr;
}

