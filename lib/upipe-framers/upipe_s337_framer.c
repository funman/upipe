/*
 * Copyright (C) 2013-2014 OpenHeadend S.A.R.L.
 *
 * Authors: Benjamin Cohen
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject
 * to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY
 * CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT,
 * TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE
 * SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

/** @file
 * @short Upipe s337f module - free incoming urefs
 */

#include <upipe/ubase.h>
#include <upipe/uprobe.h>
#include <upipe/uref.h>
#include <upipe/uref_sound_flow.h>
#include <upipe/uref_sound.h>
#include <upipe/upipe.h>
#include <upipe/udict.h>
#include <upipe/upipe_helper_upipe.h>
#include <upipe/upipe_helper_urefcount.h>
#include <upipe/upipe_helper_void.h>
#include <upipe/upipe_helper_output.h>
#include <upipe/upipe_helper_flow_def.h>
#include <upipe-framers/upipe_s337_framer.h>

#include <bitstream/smpte/337.h>

/** upipe_s337f structure */
struct upipe_s337f {
    /** refcount management structure */
    struct urefcount urefcount;

    /** pipe acting as output */
    struct upipe *output;
    /** output flow definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    /** buffered uref */
    struct uref *uref;

    /** size in samples of buffered uref */
    ssize_t samples;

    /** bits per raw sample */
    uint8_t bits;

    /** input flow definition packet */
    struct uref *flow_def_input;
    /** frame definition packet */
    struct uref *flow_def_attr;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_s337f, upipe, UPIPE_S337F_SIGNATURE);
UPIPE_HELPER_UREFCOUNT(upipe_s337f, urefcount, upipe_s337f_free)
UPIPE_HELPER_VOID(upipe_s337f);
UPIPE_HELPER_OUTPUT(upipe_s337f, output, flow_def, output_state, request_list)
UPIPE_HELPER_FLOW_DEF(upipe_s337f, flow_def_input, flow_def_attr)

/** @internal @This allocates a s337f pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or S337F in case of allocation error
 */
static struct upipe *upipe_s337f_alloc(struct upipe_mgr *mgr,
                                      struct uprobe *uprobe,
                                      uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_s337f_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);

    upipe_s337f_init_urefcount(upipe);
    upipe_s337f_init_output(upipe);
    upipe_s337f_init_flow_def(upipe);
    upipe_s337f->uref = NULL;

    upipe_throw_ready(&upipe_s337f->upipe);
    return &upipe_s337f->upipe;
}

/** @internal @This finds the position of the s337m sync word in the frame
 */
static ssize_t upipe_s337f_sync(struct upipe *upipe, struct uref *uref)
{
    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);

    size_t size = 0;
    uref_sound_size(uref, &size, NULL);

    if (upipe_s337f->bits == 16) {
        // TODO
        const int16_t *in;
        uref_sound_read_int16_t(uref, 0, -1, &in, 1);

        for (size_t i = 0; i < size; i++) // TODO: find sample
            if ((in[2*i+0] == (int16_t)0xf872 && in[2*i+1] == 0x4e1f)) {
                uref_sound_unmap(uref, 0, -1, 1);
                return i;
            }

        uref_sound_unmap(uref, 0, -1, 1);
    } else {
        const int32_t *in;
        uref_sound_read_int32_t(uref, 0, -1, &in, 1);

        for (size_t i = 0; i < size; i++)
            if ((in[2*i+0] == (0x6f872 << 12) && in[2*i+1] == (0x54e1f << 12)) ||
                    ((in[2*i+0] == (0x96f872 << 8) && in[2*i+1] == (0xa54e1f << 8)))) {
                uref_sound_unmap(uref, 0, -1, 1);
                return i;
            }

        uref_sound_unmap(uref, 0, -1, 1);
    }

    return -1;
}

static void upipe_s337f_header(struct upipe *upipe, int32_t *buf, uint32_t *hdr)
{
    int bits = (buf[0] == 0x6f872 << 12) ? 20 : 24;

    hdr[0] = buf[2] >> 16;
    hdr[1] = buf[3] >> (32 - bits);
}

/** @internal
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_s337f_input(struct upipe *upipe, struct uref *uref, struct upump **upump_p)
{
    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);
    struct uref *output = upipe_s337f->uref;

    ssize_t sync = upipe_s337f_sync(upipe, uref);

    if (sync == -1) {
        if (output) {
            upipe_err(upipe, "Sync lost");
            uref_free(output);
            upipe_s337f->uref = NULL;
        }
        output = uref;
        goto out;
    } else if (!output) {
        upipe_notice(upipe, "Found synchro");
    }

    // TODO
    if (upipe_s337f->bits == 16) {
        uref_free(uref);
        upipe_notice(upipe, "16-bits SMPTE 337 not handled yet");
        return;
    }

    if (output) {
        size_t size[2];
        uref_sound_size(uref, &size[0], NULL);
        uref_sound_size(output, &size[1], NULL);

        const int32_t *in;
        if (!ubase_check(uref_sound_read_int32_t(uref, 0, sync, &in, 1))) {
            upipe_err(upipe, "Could not map audio uref for reading");
        }

        int32_t *out;
        if (!ubase_check(uref_sound_write_int32_t(output, 0, -1, &out, 1))) {
            upipe_err(upipe, "Could not map buffered audio uref for writing");
        }

        size_t out_size = size[0] - upipe_s337f->samples;
        if (out_size < sync) {
            upipe_verbose_va(upipe, "Reducing frame size from %zu to %zu",
                upipe_s337f->samples + sync,
                upipe_s337f->samples + out_size);
            out_size = sync;
        }

        out_size *= 2; /* channels */
        out_size *= 4; /* s32 */
        memcpy(&out[2*upipe_s337f->samples], in, out_size);

        uint32_t hdr[2]; /* Pc + Pd */
        upipe_s337f_header(upipe, out, hdr);

        unsigned data_stream_number =  hdr[0] >> 13;
        unsigned data_type_dependent= (hdr[0] >>  8) & 0x1f;
        unsigned error_flag         = (hdr[0] >>  7) & 0x1;
        unsigned data_mode          = (hdr[0] >>  5) & 0x3;
        unsigned data_type          = (hdr[0] >>  0) & 0x1f;

        if (error_flag)
            upipe_err(upipe, "error flag set");

        struct uref *flow_def = upipe_s337f_alloc_flow_def_attr(upipe);
        if (unlikely(flow_def == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        } else {
            size_t frame_size = size[0];
            if (frame_size == 1601 || frame_size == 1602) { /* NTSC */
                uref_clock_set_latency(flow_def, UCLOCK_FREQ * 2 * 1001 / 30000);
            } else
                uref_clock_set_latency(flow_def, UCLOCK_FREQ * 2 * frame_size / 48000);

            switch (data_type) {
            case S337_TYPE_DOLBY_E:
                UBASE_FATAL(upipe, uref_flow_set_def(flow_def, "sound.s32.s337.dolbye."))
                break;
            case S337_TYPE_A52:
                UBASE_FATAL(upipe, uref_flow_set_def(flow_def, "sound.s32.s337.a52."))
                break;
            case S337_TYPE_A52E:
                UBASE_FATAL(upipe, uref_flow_set_def(flow_def, "sound.s32.s337.a52e."))
                break;
            default:
                upipe_warn_va(upipe, "Unhandled data type %u", data_type);
            }

            flow_def = upipe_s337f_store_flow_def_attr(upipe, flow_def);
            if (flow_def)
                upipe_s337f_store_flow_def(upipe, flow_def);
        }

        size_t samples = hdr[1] / upipe_s337f->bits / 2 /* channels */ + 2 /* header */;
        if (samples > size[0]) {
            upipe_err_va(upipe, "S337 frame truncated");
        }

        if (0) {
            upipe_notice_va(upipe, "%d %d %d %d %d", data_stream_number,
                    data_type_dependent, error_flag, data_mode, data_type);
            upipe_notice_va(upipe, "%u bytes", hdr[1] / 8);
        }

        uref_sound_unmap(uref, 0, sync, 1);
        uref_sound_unmap(output, 0, -1, 1);
    }

    /* discard leading samples up to sync word */
    int32_t *samples;
    if (ubase_check(uref_sound_write_int32_t(uref, 0, -1, &samples, 1))) {
        size_t size;
        uref_sound_size(uref, &size, NULL);
        size_t s = 2 /* stereo */ * 4 /* s32 */ * (size - sync);
        memmove(samples, &samples[2*sync], s); // discard up to sync word

        uref_sound_unmap(uref, 0, -1, 1);
        upipe_s337f->samples = size - sync;
    } else {
        upipe_err(upipe, "Could not map audio uref for writing");
    }

    /* buffer next uref */
    upipe_s337f->uref = uref;

out:
    if (!upipe_s337f->flow_def)
        upipe_s337f_store_flow_def(upipe, uref_dup(upipe_s337f->flow_def_input));

    if (output)
        upipe_s337f_output(upipe, output, upump_p);
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_s337f_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);

    if (flow_def == NULL)
        return UBASE_ERR_INVALID;

    const char *def;
    if (unlikely(!ubase_check(uref_flow_get_def(flow_def, &def))))
        return UBASE_ERR_INVALID;

    uint8_t bits;
    if (!ubase_ncmp(def, "sound.s32.")) {
        bits = 32;
    } else if (!ubase_ncmp(def, "sound.s32.")) {
        bits = 16;
    } else {
        return UBASE_ERR_INVALID;
    }

    if (bits == 32 && unlikely(!ubase_check(uref_sound_flow_get_raw_sample_size(flow_def, &bits)))) {
        return UBASE_ERR_INVALID;
    }

    upipe_s337f->bits = bits;

    uint8_t planes = 0;
    if (unlikely(!ubase_check(uref_sound_flow_get_planes(flow_def, &planes) ||
                    planes != 1)))
        return UBASE_ERR_INVALID;

    uint8_t channels = 0;
    if (unlikely(!ubase_check(uref_sound_flow_get_channels(flow_def, &channels) ||
                channels != 2)))
        return UBASE_ERR_INVALID;

    struct uref *flow_def_dup = uref_dup(flow_def);

    if (unlikely(flow_def_dup == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return UBASE_ERR_ALLOC;
    }

    flow_def = upipe_s337f_store_flow_def_input(upipe, flow_def_dup);
    if (flow_def != NULL)
        upipe_s337f_store_flow_def(upipe, flow_def);

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_s337f_control(struct upipe *upipe, int command, va_list args)
{
    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);
    switch (command) {
        case UPIPE_REGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            return upipe_s337f_alloc_output_proxy(upipe, request);
        }
        case UPIPE_UNREGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            return upipe_s337f_free_output_proxy(upipe, request);
        }

        case UPIPE_GET_FLOW_DEF: {
            struct uref **p = va_arg(args, struct uref **);
            return upipe_s337f_get_flow_def(upipe, p);
        }
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_s337f_set_flow_def(upipe, flow_def);
        }
        case UPIPE_GET_OUTPUT: {
            struct upipe **p = va_arg(args, struct upipe **);
            return upipe_s337f_get_output(upipe, p);
        }
        case UPIPE_SET_OUTPUT: {
            struct upipe *output = va_arg(args, struct upipe *);
            return upipe_s337f_set_output(upipe, output);
        }

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @internal @This frees all resources allocated.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_s337f_free(struct upipe *upipe)
{
    struct upipe_s337f *upipe_s337f = upipe_s337f_from_upipe(upipe);

    upipe_throw_dead(upipe);
    upipe_s337f_clean_urefcount(upipe);
    upipe_s337f_clean_output(upipe);
    upipe_s337f_clean_flow_def(upipe);
    uref_free(upipe_s337f->uref);

    upipe_s337f_free_void(upipe);
}

static struct upipe_mgr upipe_s337f_mgr = {
    .refcount = NULL,
    .signature = UPIPE_S337F_SIGNATURE,

    .upipe_alloc = upipe_s337f_alloc,
    .upipe_input = upipe_s337f_input,
    .upipe_control = upipe_s337f_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for s337f pipes
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_s337f_mgr_alloc(void)
{
    return &upipe_s337f_mgr;
}
