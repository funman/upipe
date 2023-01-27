/*
 * Copyright (C) 2023 Open Broadcast Systems Ltd
 *
 * Authors: Rafaël Carré
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
 * @short Upipe module for SRT handshakes
 */

#include "upipe/ubase.h"
#include "upipe/uclock.h"
#include "upipe/uref.h"
#include "upipe/uref_block.h"
#include "upipe/uref_block_flow.h"
#include "upipe/uref_clock.h"
#include "upipe/upipe.h"
#include "upipe/upipe_helper_upipe.h"
#include "upipe/upipe_helper_subpipe.h"
#include "upipe/upipe_helper_urefcount.h"
#include "upipe/upipe_helper_urefcount_real.h"
#include "upipe/upipe_helper_void.h"
#include "upipe/upipe_helper_uref_mgr.h"
#include "upipe/upipe_helper_ubuf_mgr.h"
#include "upipe/upipe_helper_output.h"
#include "upipe/upipe_helper_upump_mgr.h"
#include "upipe/upipe_helper_upump.h"
#include "upipe/upipe_helper_uclock.h"

#include "upipe-modules/upipe_srt_handshake.h"

#include <bitstream/haivision/srt.h>

#include <arpa/inet.h>
#include <limits.h>


/** @hidden */
static int upipe_srt_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a SRT handshake pipe. */
struct upipe_srt {
    /** real refcount management structure */
    struct urefcount urefcount_real;
    /** refcount management structure exported to the public structure */
    struct urefcount urefcount;

    struct upipe_mgr sub_mgr;
    /** list of output subpipes */
    struct uchain outputs;

    struct upump_mgr *upump_mgr;
    struct upump *upump_timer;
    struct upump *upump_timer_lost;
    struct uclock *uclock;
    struct urequest uclock_request;


    /** uref manager */
    struct uref_mgr *uref_mgr;
    /** uref manager request */
    struct urequest uref_mgr_request;

    /** ubuf manager */
    struct ubuf_mgr *ubuf_mgr;
    /** flow format packet */
    struct uref *flow_format;
    /** ubuf manager request */
    struct urequest ubuf_mgr_request;

    /** pipe acting as output */
    struct upipe *output;
    /** flow definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    uint32_t syn_cookie;
    uint32_t socket_id;

    bool expect_conclusion;

    struct upipe *srt_output;

    struct uchain queue;
    /** expected sequence number */
    uint64_t expected_seqnum;

    /** last seq output */
    uint64_t last_output_seqnum;

    uint64_t last_ack;

    uint32_t ack_num;

    /* stats */
    size_t buffered;
    size_t nacks;
    size_t repaired;
    size_t loss;
    size_t dups;

    /** buffer latency */
    uint64_t latency;
    /** last time a NACK was sent */
    uint64_t last_nack[65536];

    uint64_t rtt;
    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_srt, upipe, UPIPE_SRT_HANDSHAKE_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_srt, urefcount, upipe_srt_no_input)
UPIPE_HELPER_UREFCOUNT_REAL(upipe_srt, urefcount_real, upipe_srt_free);

UPIPE_HELPER_VOID(upipe_srt)

UPIPE_HELPER_OUTPUT(upipe_srt, output, flow_def, output_state, request_list)
UPIPE_HELPER_UPUMP_MGR(upipe_srt, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_srt, upump_timer, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_srt, upump_timer_lost, upump_mgr)
UPIPE_HELPER_UCLOCK(upipe_srt, uclock, uclock_request, NULL, upipe_throw_provide_request, NULL)

UPIPE_HELPER_UREF_MGR(upipe_srt, uref_mgr, uref_mgr_request,
                      upipe_srt_check,
                      upipe_srt_register_output_request,
                      upipe_srt_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srt, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srt_check,
                      upipe_srt_register_output_request,
                      upipe_srt_unregister_output_request)

/** @internal @This is the private context of a SRT handshake output pipe. */
struct upipe_srt_output {
    /** refcount management structure */
    struct urefcount urefcount;
    /** structure for double-linked lists */
    struct uchain uchain;

    /** uref manager */
    struct uref_mgr *uref_mgr;
    /** uref manager request */
    struct urequest uref_mgr_request;

    /** ubuf manager */
    struct ubuf_mgr *ubuf_mgr;
    /** flow format packet */
    struct uref *flow_format;
    /** ubuf manager request */
    struct urequest ubuf_mgr_request;

    /** pipe acting as output */
    struct upipe *output;
    /** flow definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    /** public upipe structure */
    struct upipe upipe;
};

static int upipe_srt_output_check(struct upipe *upipe, struct uref *flow_format);
UPIPE_HELPER_UPIPE(upipe_srt_output, upipe, UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
UPIPE_HELPER_VOID(upipe_srt_output);
UPIPE_HELPER_UREFCOUNT(upipe_srt_output, urefcount, upipe_srt_output_free)
UPIPE_HELPER_OUTPUT(upipe_srt_output, output, flow_def, output_state, request_list)
UPIPE_HELPER_UREF_MGR(upipe_srt_output, uref_mgr, uref_mgr_request,
                      upipe_srt_output_check,
                      upipe_srt_output_register_output_request,
                      upipe_srt_output_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srt_output, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srt_output_check,
                      upipe_srt_output_register_output_request,
                      upipe_srt_output_unregister_output_request)
UPIPE_HELPER_SUBPIPE(upipe_srt, upipe_srt_output, output, sub_mgr, outputs,
                     uchain)

static int upipe_srt_output_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srt_output *upipe_srt_output = upipe_srt_output_from_upipe(upipe);
    if (flow_format)
        upipe_srt_output_store_flow_def(upipe, flow_format);

    if (upipe_srt_output->uref_mgr == NULL) {
        upipe_srt_output_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt_output->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srt_output->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srt_output_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    return UBASE_ERR_NONE;
}

/** @This is called when there is no external reference to the pipe anymore.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_no_input(struct upipe *upipe)
{
    upipe_srt_throw_sub_outputs(upipe, UPROBE_SOURCE_END);
    upipe_srt_release_urefcount_real(upipe);
}
/** @internal @This allocates an output subpipe of a dup pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srt_output_alloc(struct upipe_mgr *mgr,
                                            struct uprobe *uprobe,
                                            uint32_t signature, va_list args)
{
    if (mgr->signature != UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
        return NULL;

    struct upipe_srt *upipe_srt = upipe_srt_from_sub_mgr(mgr);
    if (upipe_srt->srt_output)
        return NULL;

    struct upipe *upipe = upipe_srt_output_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

//    struct upipe_srt_output *upipe_srt_output = upipe_srt_output_from_upipe(upipe);

    upipe_srt->srt_output = upipe;

    upipe_srt_output_init_urefcount(upipe);
    upipe_srt_output_init_output(upipe);
    upipe_srt_output_init_sub(upipe);
    upipe_srt_output_init_ubuf_mgr(upipe);
    upipe_srt_output_init_uref_mgr(upipe);

    upipe_throw_ready(upipe);

    upipe_srt_output_require_uref_mgr(upipe);

    return upipe;
}


/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_output_free(struct upipe *upipe)
{
    //struct upipe_srt_output *upipe_srt_output = upipe_srt_output_from_upipe(upipe);
    upipe_throw_dead(upipe);

    struct upipe_srt *upipe_srt = upipe_srt_from_sub_mgr(upipe->mgr);
    upipe_srt->srt_output = NULL;
    upipe_srt_output_clean_output(upipe);
    upipe_srt_output_clean_sub(upipe);
    upipe_srt_output_clean_urefcount(upipe);
    upipe_srt_output_clean_ubuf_mgr(upipe);
    upipe_srt_output_clean_uref_mgr(upipe);
    upipe_srt_output_free_void(upipe);
}

/** @internal @This sends a retransmission request for a number of seqnums.
 *
 * @param upipe description structure of the pipe
 * @param lost_seqnum First sequence number missing
 * @param seqnum First sequence number NOT missing
 * @param ssrc TODO
 */
static void upipe_srt_output_lost(struct upipe *upipe, uint16_t lost_seqnum, uint16_t seqnum, uint8_t *ssrc)
{
    //struct upipe_srt_output *upipe_srt_output = upipe_srt_output_from_upipe(upipe);
    //struct upipe_srt *upipe_srt = upipe_srt_from_sub_mgr(upipe->mgr);

#if 0
    /* Send a single NACK packet, with a single FCI */
    int s = RTCP_FB_HEADER_SIZE + 1 * RTCP_FB_FCI_GENERIC_NACK_SIZE;

    /* Allocate NACK packet */
    struct uref *pkt = uref_block_alloc(upipe_srt_output->uref_mgr,
        upipe_srt_output->ubuf_mgr, s);
    if (unlikely(!pkt)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return;
    }

    uint8_t *buf;
    uref_block_write(pkt, 0, &s, &buf);
    memset(buf, 0, s);

    /* Header */
    rtcp_set_rtp_version(buf);
    rtcp_fb_set_fmt(buf, RTCP_PT_RTPFB_GENERIC_NACK);
    rtcp_set_pt(buf, RTCP_PT_RTPFB);

    // TODO : make receiver SSRC configurable
    uint8_t ssrc_sender[4] = { 0x1, 0x2, 0x3, 0x4 };
    rtcp_fb_set_ssrc_pkt_sender(buf, ssrc_sender);
    rtcp_fb_set_ssrc_media_src(buf, ssrc);

    uint8_t *fci = &buf[RTCP_FB_HEADER_SIZE];
    rtcp_fb_nack_set_packet_id(fci, lost_seqnum);

    uint16_t pkts = seqnum - 1 - lost_seqnum;
    // TODO : add several FCI if more than 17 packets are missing
    if (pkts > 16)
        pkts = 16;

    uint16_t bits = 0;
    for (size_t i = 0; i < pkts; i++)
        bits |= 1 << i;

    rtcp_fb_nack_set_bitmask_lost(fci, bits);
    upipe_srt->nacks += pkts + 1;

    rtcp_set_length(buf, s / 4 - 1);

    upipe_verbose_va(upipe, "NACKing %hu (+0x%hx)", lost_seqnum, bits);

    uref_block_unmap(pkt, 0);

    // XXX : date NACK packet?
    //uref_clock_set_date_sys(pkt, /* cr */ 0, UREF_DATE_CR);

    upipe_srt_output_output(upipe, pkt, NULL);
#endif
}

static uint64_t _upipe_srt_get_rtt(struct upipe *upipe)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    /* VSF TR-06 doesn't give a mean to retrieve RTT, but defaults to 7
     * retransmissions requests per packet.
     * XXX: make it configurable ? */

    uint64_t rtt = upipe_srt->rtt;
    if (!rtt)
        rtt = upipe_srt->latency / 7;
    return rtt;
}


/** @internal @This periodic timer checks for missing seqnums.
 */
static void upipe_srt_timer_lost(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    uint64_t expected_seq = UINT64_MAX;

    uint64_t rtt = _upipe_srt_get_rtt(upipe);

    uint64_t now = uclock_now(upipe_srt->uclock);

    /* space out NACKs a bit more than RTT. XXX: tune me */
    uint64_t next_nack = now - rtt * 12 / 10;

    /* TODO: do not look at the last pkts/s * rtt
     * It it too late to send a NACK for these
     * XXX: use cr_sys, because pkts/s also accounts for
     * the retransmitted packets */

    struct uchain *uchain;
    int holes = 0;
    ulist_foreach(&upipe_srt->queue, uchain) {
        struct uref *uref = uref_from_uchain(uchain);
        uint64_t seqnum = 0;
        uref_attr_get_priv(uref, &seqnum);

        if (likely(expected_seq != UINT64_MAX) && seqnum != expected_seq) {
            /* hole found */
            upipe_dbg_va(upipe, "Found hole from %"PRIu64" (incl) to %"PRIu64" (excl)",
                expected_seq, seqnum);

            for (uint32_t seq = expected_seq; seq != seqnum; seq++) {
                /* if packet was lost, we should have detected it already */
                if (upipe_srt->last_nack[seq & 0xffff] == 0) {
                    upipe_err_va(upipe, "packet %hu missing but was not marked as lost!", seq);
                    continue;
                }

                /* if we sent a NACK not too long ago, do not repeat it */
                /* since NACKs are sent in a batch, break loop if the first packet is too early */
                if (upipe_srt->last_nack[seq & 0xffff] > next_nack) {
                    if (0) upipe_err_va(upipe, "Cancelling NACK due to RTT (seq %hu diff %"PRId64"",
                        seq, next_nack - upipe_srt->last_nack[seq & 0xffff]
                    );
                    goto next;
                }
            }

            /* update NACK request time */
            for (uint32_t seq = expected_seq; seq != seqnum; seq++) {
                upipe_srt->last_nack[seq & 0xffff] = now;
            }

            /* TODO:
                - check the following packets to fill in bitmask
                - send request in a single batch (multiple FCI)
             */
            upipe_srt_output_lost(upipe, expected_seq, seqnum, 0);
            holes++;
        }

next:
        expected_seq = (seqnum + 1) & UINT32_MAX;
    }

    if (upipe_srt->buffered == 0)
        return;

    // A Full ACK control packet is sent every 10 ms and has all the fields of Figure 13.
    if (upipe_srt->last_ack == UINT64_MAX || (now - upipe_srt->last_ack > UCLOCK_FREQ / 100)) {
        struct uref *uref = uref_block_alloc(upipe_srt->uref_mgr,
                upipe_srt->ubuf_mgr, SRT_HEADER_SIZE + SRT_ACK_CIF_SIZE_3);
        if (uref) {
            uint8_t *out;
            int output_size = -1;
            if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
                uref_free(uref);
                upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            } else {
                srt_set_packet_control(out, true);
                srt_set_packet_timestamp(out, 0); // TODO
                srt_set_packet_dst_socket_id(out, 0);
                srt_set_control_packet_type(out, SRT_CONTROL_TYPE_ACK);
                srt_set_control_packet_subtype(out, 0);
                srt_set_control_packet_type_specific(out, upipe_srt->ack_num++);
                uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);

                uint64_t last_seq = 0;
                uref_attr_get_priv(uref_from_uchain(upipe_srt->queue.prev), &last_seq);
                srt_set_ack_last_ack_seq(out_cif, last_seq);
                srt_set_ack_rtt(out_cif, 1000);
                srt_set_ack_rtt_variance(out_cif, 100);
                srt_set_ack_avail_bufsize(out_cif, 100);
                srt_set_ack_packets_receiving_rate(out_cif, 100);
                srt_set_ack_estimated_link_capacity(out_cif, 1000);
                srt_set_ack_receiving_rate(out_cif, 100000);

                uref_block_unmap(uref, 0);
                upipe_srt_output(upipe, uref, NULL);
                printf("send ack\n");
            }
        }
    }

    if (holes) { /* debug stats */
        uint64_t now = uclock_now(upipe_srt->uclock);
        static uint64_t old;
        if (likely(old != 0))
            upipe_dbg_va(upipe, "%d holes after %"PRIu64" ms",
                    holes, 1000 * (now - old) / UCLOCK_FREQ);
        old = now;
    }
}

/** @internal @This periodic timer remove seqnums from the buffer.
 */
static void upipe_srt_timer(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    uint64_t now = uclock_now(upipe_srt->uclock);

    struct uchain *uchain, *uchain_tmp;
    ulist_delete_foreach(&upipe_srt->queue, uchain, uchain_tmp) {
        struct uref *uref = uref_from_uchain(uchain);
        uint64_t seqnum = 0;
        if (!ubase_check(uref_attr_get_priv(uref, &seqnum))) {
            upipe_err_va(upipe, "Could not read seqnum from uref");
        }

        uint64_t cr_sys = 0;
        if (unlikely(!ubase_check(uref_clock_get_cr_sys(uref, &cr_sys))))
            upipe_warn_va(upipe, "Couldn't read cr_sys in %s()", __func__);

        if (now - cr_sys <= upipe_srt->latency)
            break;

        upipe_verbose_va(upipe, "Output seq %"PRIu64" after %"PRIu64" clocks", seqnum, now - cr_sys);
        if (likely(upipe_srt->last_output_seqnum != UINT_MAX)) {
            uint32_t diff = seqnum - upipe_srt->last_output_seqnum - 1;
            if (diff) {
                upipe_srt->loss += diff;
                upipe_dbg_va(upipe, "PKT LOSS: %" PRIu64 " -> %"PRIu64" DIFF %hu",
                        upipe_srt->last_output_seqnum, seqnum, diff);
            }
        }

        upipe_srt->last_output_seqnum = seqnum;

        ulist_delete(uchain);
        upipe_srt_output_output(upipe_srt->srt_output, uref, NULL); // XXX: use timer upump ?
        if (--upipe_srt->buffered == 0) {
            upipe_warn_va(upipe, "Exhausted buffer");
            upipe_srt->expected_seqnum = UINT_MAX;
        }
    }
}

static void upipe_srt_restart_timer(struct upipe *upipe)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);
    uint64_t rtt = _upipe_srt_get_rtt(upipe);

    upipe_srt_set_upump_timer_lost(upipe, NULL);
    if (upipe_srt->upump_mgr) {
        struct upump *upump=
            upump_alloc_timer(upipe_srt->upump_mgr,
                              upipe_srt_timer_lost,
                              upipe, upipe->refcount,
                              0, rtt / 10);
        upump_start(upump);
        upipe_srt_set_upump_timer_lost(upipe, upump);
    }
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srt_output_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, "block."))

    if (upipe_srt->srt_output) {
        struct uref *flow_def_dup = uref_dup(flow_def);
        if (unlikely(flow_def_dup == NULL))
            return UBASE_ERR_ALLOC;
        upipe_srt_output_store_flow_def(upipe_srt->srt_output, flow_def_dup);
    }

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on an output subpipe of a dup
 * pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int _upipe_srt_output_control(struct upipe *upipe,
                                    int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_srt_output_control_super(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srt_output_control_output(upipe, command, args));
    switch (command) {
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_srt_output_set_flow_def(upipe, flow_def);
        }
        default:
            return UBASE_ERR_UNHANDLED;
    }
}
static int upipe_srt_output_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srt_output_control(upipe, command, args))
    return upipe_srt_output_check(upipe, NULL);
}

/** @internal @This handles RTCP data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_srt_output_input(struct upipe *upipe, struct uref *uref,
                                    struct upump **upump_p)
{
    struct upipe_srt_output *upipe_srt_output = upipe_srt_output_from_upipe(upipe);
    //struct upipe_srt *upipe_srt = upipe_srt_from_sub_mgr(upipe->mgr);

    if (upipe_srt_output->uref_mgr == NULL || upipe_srt_output->ubuf_mgr == NULL) {
        upipe_srt_output_check(upipe, NULL);
        uref_free(uref);
        return;
    }

    upipe_srt_output_output(upipe, uref, upump_p);
}

/** @internal @This initializes the output manager for a srt set pipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_init_sub_mgr(struct upipe *upipe)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);
    struct upipe_mgr *sub_mgr = &upipe_srt->sub_mgr;
    sub_mgr->refcount = upipe_srt_to_urefcount_real(upipe_srt);
    sub_mgr->signature = UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE;
    sub_mgr->upipe_alloc = upipe_srt_output_alloc;
    sub_mgr->upipe_input = upipe_srt_output_input;
    sub_mgr->upipe_control = upipe_srt_output_control;
}


/** @internal @This allocates a SRT handshake pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srt_alloc(struct upipe_mgr *mgr,
                                        struct uprobe *uprobe,
                                        uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_srt_alloc_void(mgr, uprobe, signature, args);
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    upipe_srt_init_urefcount(upipe);
    upipe_srt_init_urefcount_real(upipe);
    upipe_srt_init_sub_outputs(upipe);
    upipe_srt_init_sub_mgr(upipe);

    upipe_srt_init_uref_mgr(upipe);
    upipe_srt_init_ubuf_mgr(upipe);
    upipe_srt_init_output(upipe);

    upipe_srt_init_upump_mgr(upipe);
    upipe_srt_init_upump_timer(upipe);
    upipe_srt_init_upump_timer_lost(upipe);
    upipe_srt_init_uclock(upipe);
    upipe_srt_require_uclock(upipe);

    // FIXME
    upipe_srt->socket_id = 0;
    upipe_srt->syn_cookie = 1;
    upipe_srt->expect_conclusion = false;
    upipe_srt->srt_output = NULL;

    ulist_init(&upipe_srt->queue);
    memset(upipe_srt->last_nack, 0, sizeof(upipe_srt->last_nack));
    upipe_srt->rtt = 0;
    upipe_srt->expected_seqnum = UINT64_MAX;

    upipe_srt->last_output_seqnum = UINT64_MAX;
    upipe_srt->last_ack = UINT64_MAX;
    upipe_srt->ack_num = 0;
    upipe_srt->buffered = 0;
    upipe_srt->nacks = 0;
    upipe_srt->repaired = 0;
    upipe_srt->loss = 0;
    upipe_srt->dups = 0;


    upipe_srt->latency = UCLOCK_FREQ;


    upipe_throw_ready(upipe);
    return upipe;
}


/** @internal @This checks if the pump may be allocated.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_srt_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    upipe_srt_check_upump_mgr(upipe);

    if (flow_format != NULL) {
        uint64_t latency;
        if (!ubase_check(uref_clock_get_latency(flow_format, &latency)))
            latency = 0;
        uref_clock_set_latency(flow_format, latency + upipe_srt->latency);

        upipe_srt_store_flow_def(upipe, flow_format);
    }

    if (upipe_srt->flow_def == NULL)
        return UBASE_ERR_NONE;

    if (upipe_srt->uref_mgr == NULL) {
        upipe_srt_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srt->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srt_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt->upump_mgr && !upipe_srt->upump_timer) {
        struct upump *upump =
            upump_alloc_timer(upipe_srt->upump_mgr,
                              upipe_srt_timer,
                              upipe, upipe->refcount,
                              UCLOCK_FREQ/300, UCLOCK_FREQ/300);
        upump_start(upump);
        upipe_srt_set_upump_timer(upipe, upump);

        /* every 10ms, check for lost packets
         * interval is reduced each time we get the current RTT from sender */
        upipe_srt_restart_timer(upipe);
    }

    return UBASE_ERR_NONE;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srt_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;

    const char *def;
    UBASE_RETURN(uref_flow_get_def(flow_def, &def))

    if (ubase_ncmp(def, "block.")) {
        upipe_err_va(upipe, "Unknown def %s", def);
        return UBASE_ERR_INVALID;
    }

    flow_def = uref_dup(flow_def);
    if (!flow_def)
        return UBASE_ERR_ALLOC;

    upipe_srt_store_flow_def(upipe, flow_def);

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on a SRT handshake pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int _upipe_srt_control(struct upipe *upipe,
                                 int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_srt_control_output(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srt_control_outputs(upipe, command, args));

    switch (command) {
        case UPIPE_ATTACH_UPUMP_MGR:
            upipe_srt_set_upump_timer(upipe, NULL);
            upipe_srt_set_upump_timer_lost(upipe, NULL);
            return upipe_srt_attach_upump_mgr(upipe);

        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow = va_arg(args, struct uref *);
            return upipe_srt_set_flow_def(upipe, flow);
        }

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @internal @This processes control commands on a SRT handshake pipe, and
 * checks the status of the pipe afterwards.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_srt_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srt_control(upipe, command, args));

    return upipe_srt_check(upipe, NULL);
}

static const char ctrl_type[][10] =
{
    [SRT_CONTROL_TYPE_HANDSHAKE] = "handshake",
    [SRT_CONTROL_TYPE_KEEPALIVE] = "keepalive",
    [SRT_CONTROL_TYPE_ACK] = "ack",
    [SRT_CONTROL_TYPE_NAK] = "nak",
    [SRT_CONTROL_TYPE_SHUTDOWN] = "shutdown",
    [SRT_CONTROL_TYPE_ACKACK] = "ackack",
    [SRT_CONTROL_TYPE_DROPREQ] = "dropreq",
    [SRT_CONTROL_TYPE_PEERERROR] = "peererror",
};

static const char *get_ctrl_type(uint16_t type)
{
    if (type == SRT_CONTROL_TYPE_USER)
        return "user";
    if (type >= (sizeof(ctrl_type) / sizeof(*ctrl_type)))
        return "?";
    return ctrl_type[type];
}

static struct uref *upipe_srt_input_control(struct upipe *upipe, const uint8_t *buf, int size)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    uint16_t type = srt_get_control_packet_type(buf);
    printf("control %s\n", get_ctrl_type(type));
    if (type == SRT_CONTROL_TYPE_HANDSHAKE) {
        const uint8_t *cif = srt_get_control_packet_cif(buf);
        if (!srt_check_handshake(cif, size - SRT_HEADER_SIZE)) {
            upipe_err(upipe, "Malformed handshake");
            return NULL;
        }
        uint32_t version = srt_get_handshake_version(cif);
        uint16_t encryption = srt_get_handshake_encryption(cif);
        uint16_t extension = srt_get_handshake_extension(cif);
        uint32_t hs_type = srt_get_handshake_type(cif);
        uint32_t syn_cookie = srt_get_handshake_syn_cookie(cif);
        uint32_t dst_socket_id = srt_get_packet_dst_socket_id(buf);

        if (!upipe_srt->expect_conclusion) {
            if (version != 4 || encryption != SRT_HANDSHAKE_CIPHER_NONE
                    || extension != SRT_HANDSHAKE_EXT_KMREQ 
                    || hs_type != SRT_HANDSHAKE_TYPE_INDUCTION ||
                    syn_cookie != 0 || dst_socket_id != 0) {
                upipe_err(upipe, "Malformed handshake");
                return NULL;
            }

            uint32_t socket_id = srt_get_handshake_socket_id(cif);
            upipe_srt->socket_id = socket_id;
            struct sockaddr_storage addr;
            srt_get_handshake_ip(cif, (struct sockaddr *)&addr);
            char ip_str[INET6_ADDRSTRLEN];
            if (addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &(((struct sockaddr_in *)&addr)->sin_addr),
                        ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&addr)->sin6_addr),
                        ip_str, sizeof(ip_str));
            }

            printf("%s : 0x%08x\n", ip_str, socket_id);

            //
            struct uref *uref = uref_block_alloc(upipe_srt->uref_mgr,
                    upipe_srt->ubuf_mgr, SRT_HEADER_SIZE + SRT_HANDSHAKE_CIF_SIZE);
            if (!uref)
                return NULL;
            uint8_t *out;
            int output_size = -1;
            if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
                uref_free(uref);
                upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            }

            memset(out, 0, output_size);

            srt_set_packet_control(out, true);
            srt_set_packet_timestamp(out, 0); // TODO
            srt_set_packet_dst_socket_id(out, socket_id);
            srt_set_control_packet_type(out, SRT_CONTROL_TYPE_HANDSHAKE);
            srt_set_control_packet_subtype(out, 0);
            srt_set_control_packet_type_specific(out, 0);
            uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);

            memset(&addr, 0, sizeof(addr));
            struct sockaddr_in *in = (struct sockaddr_in*)&addr;
            in->sin_family = AF_INET;
            in->sin_addr.s_addr = INADDR_LOOPBACK;
            in->sin_port = htons(1234);

            srt_set_handshake_ip(out_cif, (const struct sockaddr*)&addr);

            srt_set_handshake_mtu(out_cif, 1500);
            srt_set_handshake_mfw(out_cif, 8192);
            srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION);
            srt_set_handshake_encryption(out_cif, SRT_HANDSHAKE_CIPHER_NONE);
            srt_set_handshake_extension(out_cif, SRT_MAGIC_CODE);
            srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_INDUCTION);
            srt_set_handshake_syn_cookie(out_cif, upipe_srt->syn_cookie);
            srt_set_handshake_socket_id(out_cif, socket_id);

            upipe_srt->expect_conclusion = true;

            uref_block_unmap(uref, 0);
            return uref;
        } else {
            uint32_t socket_id = srt_get_handshake_socket_id(cif);
            if (version != 5 || encryption != SRT_HANDSHAKE_CIPHER_NONE
                    || hs_type != SRT_HANDSHAKE_TYPE_CONCLUSION
                    || syn_cookie != upipe_srt->syn_cookie
                    || socket_id != upipe_srt->socket_id) {
                upipe_err(upipe, "Malformed conclusion handshake");
                upipe_srt->expect_conclusion = false;
                return NULL;
            }

            //uint32_t socket_id = srt_get_handshake_socket_id(cif);
            struct sockaddr_storage addr;
            srt_get_handshake_ip(cif, (struct sockaddr *)&addr);
            char ip_str[INET6_ADDRSTRLEN];
            if (addr.ss_family == AF_INET) {
                inet_ntop(AF_INET, &(((struct sockaddr_in *)&addr)->sin_addr),
                        ip_str, sizeof(ip_str));
            } else {
                inet_ntop(AF_INET6, &(((struct sockaddr_in6 *)&addr)->sin6_addr),
                        ip_str, sizeof(ip_str));
            }

            struct uref *uref = uref_block_alloc(upipe_srt->uref_mgr,
                    upipe_srt->ubuf_mgr, size);
            if (!uref)
                return NULL;
            uint8_t *out;
            int output_size = -1;
            if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
                uref_free(uref);
                upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            }

            srt_set_packet_control(out, true);
            srt_set_packet_timestamp(out, 0);
            srt_set_packet_dst_socket_id(out, upipe_srt->socket_id);
            srt_set_control_packet_type(out, SRT_CONTROL_TYPE_HANDSHAKE);
            srt_set_control_packet_subtype(out, 0);
            srt_set_control_packet_type_specific(out, 0);
            uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);

            srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION);
            srt_set_handshake_encryption(out_cif, SRT_HANDSHAKE_CIPHER_NONE);
            srt_set_handshake_extension(out_cif, extension);
            srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_CONCLUSION);
            srt_set_handshake_syn_cookie(out_cif, 0);
            srt_set_handshake_socket_id(out_cif, upipe_srt->socket_id);
            srt_set_handshake_isn(out_cif, srt_get_handshake_isn(cif));
            srt_set_handshake_mtu(out_cif, 1500);
            srt_set_handshake_mfw(out_cif, 8192);

            memset(&addr, 0, sizeof(addr));
            printf("IP %s\n", ip_str);
            srt_set_handshake_ip(out_cif, (const struct sockaddr*)&addr);

            srt_set_handshake_extension_type(out_cif, srt_get_handshake_extension_type(cif));
            uint16_t ext_len = srt_get_handshake_extension_len(cif);
            srt_set_handshake_extension_len(out_cif, ext_len);

            // TODO : interpret ext
            memcpy(((uint8_t*)srt_get_handshake_extension_buf(out_cif)),
                    srt_get_handshake_extension_buf(cif),
                    4 * ext_len);

            upipe_srt->expect_conclusion = false;

            uref_block_unmap(uref, 0);
            return uref;
        }
    } else if (type == SRT_CONTROL_TYPE_KEEPALIVE) {
    } else if (type == SRT_CONTROL_TYPE_ACK) {
    } else if (type == SRT_CONTROL_TYPE_NAK) {
    }

    return NULL;
}

/* returns true if uref was inserted in the queue */
static bool upipe_srt_insert_inner(struct upipe *upipe, struct uref *uref,
        const uint32_t seqnum, struct uref *next)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);
    uint64_t next_seqnum = 0;
    uref_attr_get_priv(next, &next_seqnum);

    uint16_t diff = seqnum - next_seqnum;
    if (!diff) {
        upipe_verbose_va(upipe, "dropping duplicate %hu", seqnum);
        upipe_srt->dups++;
        uref_free(uref);
        return true;
    }

    /* browse the list until we find a seqnum bigger than ours */
    if (diff < 0x8000) // seqnum > next_seqnum
        return false;

    /* if there's no previous packet we're too late */
    struct uchain *uchain = uref_to_uchain(next);
    if (unlikely(ulist_is_first(&upipe_srt->queue, uchain))) {
        upipe_dbg_va(upipe,
                "LATE packet drop: Expected %" PRIu64 ", got %u, didn't insert after %"PRIu64,
                upipe_srt->expected_seqnum, seqnum, next_seqnum);
        uref_free(uref);
        return true;
    }

    /* Read previous packet seq & cr_sys */
    uint64_t prev_seqnum = 0, cr_sys = 0;

    struct uref *prev = uref_from_uchain(uchain->prev);
    uref_attr_get_priv(prev, &prev_seqnum);

    /* overwrite this uref' cr_sys with previous one's
     * so it get scheduled at the right time */
    if (ubase_check(uref_clock_get_cr_sys(prev, &cr_sys)))
        uref_clock_set_cr_sys(uref, cr_sys);
    else
        upipe_err_va(upipe, "Couldn't read cr_sys in %s() - %zu buffered",
                __func__, upipe_srt->buffered);

    upipe_srt->buffered++;
    ulist_insert(uchain->prev, uchain, uref_to_uchain(uref));
    upipe_srt->repaired++;
    upipe_srt->last_nack[seqnum] = 0;

    upipe_dbg_va(upipe, "Repaired %"PRIu64" > %hu > %"PRIu64" -diff %d",
            prev_seqnum, seqnum, next_seqnum, -diff);

    return true;
}

static bool upipe_srt_insert(struct upipe *upipe, struct uref *uref, const uint32_t seqnum)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    struct uchain *uchain, *uchain_tmp;
    ulist_delete_foreach(&upipe_srt->queue, uchain, uchain_tmp) {
        struct uref *next = uref_from_uchain(uchain);
        if (upipe_srt_insert_inner(upipe, uref, seqnum, next))
            return true;
    }

    /* Could not insert packet */
    return false;
}

static void upipe_srt_input(struct upipe *upipe, struct uref *uref,
        struct upump **upump_p)
{
    struct upipe_srt *upipe_srt = upipe_srt_from_upipe(upipe);

    size_t total_size;
    ubase_assert(uref_block_size(uref, &total_size));

    const uint8_t *buf;
    int size = total_size;

    ubase_assert(uref_block_read(uref, 0, &size, &buf));
    assert(size == total_size);

    if (size < SRT_HEADER_SIZE) {
        upipe_err_va(upipe, "Packet too small (%d)", size);
        ubase_assert(uref_block_unmap(uref, 0));
        uref_free(uref);
        return;
    }

    if (srt_get_packet_control(buf)) {
        ubase_assert(uref_block_unmap(uref, 0));
        struct uref *reply = upipe_srt_input_control(upipe, buf, size);
        if (reply)
            upipe_srt_output(upipe, reply, upump_p);
        uref_free(uref);
        return;
    }

/* data */
    assert(upipe_srt->srt_output);

    uint32_t seqnum = srt_get_data_packet_seq(buf);
    uint32_t position = srt_get_data_packet_position(buf);
    bool order = srt_get_data_packet_order(buf);
    uint8_t encryption = srt_get_data_packet_encryption(buf);
    bool retransmit = srt_get_data_packet_retransmit(buf);
    uint32_t num = srt_get_data_packet_message_number(buf);
    uint32_t ts = srt_get_packet_timestamp(buf);
    uint32_t socket_id = srt_get_packet_dst_socket_id(buf);
    ubase_assert(uref_block_unmap(uref, 0));

    uref_block_resize(uref, SRT_HEADER_SIZE, -1); /* skip SRT header */
    upipe_dbg_va(upipe, "Data seq %u", seqnum);

    (void)order;
    (void)num;
    (void)retransmit; // stats?
    (void)ts; // TODO (µs)
    (void)socket_id; // ?

    /* store seqnum in uref */
    uref_attr_set_priv(uref, seqnum);
    if (position != 3) {
        upipe_err_va(upipe, "PP %d not handled for live streaming", position);
        uref_free(uref);
        return;
    }
    if (encryption != SRT_DATA_ENCRYPTION_CLEAR) {
        upipe_err(upipe, "Encryption not yet handled");
        uref_free(uref);
        return;
    }

    /* first packet */
    if (unlikely(upipe_srt->expected_seqnum == UINT64_MAX))
        upipe_srt->expected_seqnum = seqnum;

    uint32_t diff = seqnum - upipe_srt->expected_seqnum;

    if (diff < 0x80000000) { // seqnum > last seq, insert at the end
        /* packet is from the future */
        upipe_srt->buffered++;
        ulist_add(&upipe_srt->queue, uref_to_uchain(uref));
        upipe_srt->last_nack[seqnum & 0xffff] = 0;

        if (diff != 0) {
            uint64_t rtt = _upipe_srt_get_rtt(upipe);
            /* wait a bit to send a NACK, in case of reordering */
            uint64_t fake_last_nack = uclock_now(upipe_srt->uclock) - rtt;
            for (uint32_t seq = upipe_srt->expected_seqnum; seq != seqnum; seq++)
                if (upipe_srt->last_nack[seq & 0xffff] == 0)
                    upipe_srt->last_nack[seq & 0xffff] = fake_last_nack;
        }

        upipe_srt->expected_seqnum = seqnum + 1;
        return;
    }

    /* packet is from the past, reordered or retransmitted */
    if (upipe_srt_insert(upipe, uref, seqnum))
        return;

    uint64_t first_seq = 0, last_seq = 0;
    uref_attr_get_priv(uref_from_uchain(upipe_srt->queue.next), &first_seq);
    uref_attr_get_priv(uref_from_uchain(upipe_srt->queue.prev), &last_seq);
    // XXX : when much too late, it could mean RTP source restart
    upipe_err_va(upipe, "LATE packet %hu, dropped (buffered %"PRIu64" -> %"PRIu64")",
            seqnum, first_seq, last_seq);
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_free(struct upipe *upipe)
{
    upipe_throw_dead(upipe);

    upipe_srt_clean_output(upipe);
    upipe_srt_clean_upump_timer(upipe);
    upipe_srt_clean_upump_timer_lost(upipe);
    upipe_srt_clean_upump_mgr(upipe);
    upipe_srt_clean_uclock(upipe);
    upipe_srt_clean_ubuf_mgr(upipe);
    upipe_srt_clean_uref_mgr(upipe);
    upipe_srt_clean_urefcount(upipe);
    upipe_srt_clean_urefcount_real(upipe);
    upipe_srt_clean_sub_outputs(upipe);
    upipe_srt_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_srt_mgr = {
    .refcount = NULL,
    .signature = UPIPE_SRT_HANDSHAKE_SIGNATURE,

    .upipe_alloc = upipe_srt_alloc,
    .upipe_input = upipe_srt_input,
    .upipe_control = upipe_srt_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all SRT handshake sources
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_srt_mgr_alloc(void)
{
    return &upipe_srt_mgr;
}
