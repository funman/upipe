/*
 * Copyright (C) 2012-2015 OpenHeadend S.A.R.L.
 *
 * Authors: Christophe Massiot
 *          Benjamin Cohen
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
 *
 * The following comes from libfabric v1.9.1-42-g617566eab util/pingpong.c
 *
 * Copyright (c) 2013-2015 Intel Corporation.  All rights reserved.
 * Copyright (c) 2014-2016, Cisco Systems, Inc. All rights reserved.
 * Copyright (c) 2015 Los Alamos Nat. Security, LLC. All rights reserved.
 * Copyright (c) 2016 Cray Inc.  All rights reserved.
 * Copyright (c) 2021 Open Broadcast Systems Ltd.
 *
 * This software is available to you under the BSD license below:
 *
 *     Redistribution and use in source and binary forms, with or
 *     without modification, are permitted provided that the following
 *     conditions are met:
 *
 *      - Redistributions of source code must retain the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer.
 *
 *      - Redistributions in binary form must reproduce the above
 *        copyright notice, this list of conditions and the following
 *        disclaimer in the documentation and/or other materials
 *        provided with the distribution.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

/** @file
 * @short Upipe source module for udp sockets
 */

#include <upipe/ubase.h>
#include <upipe/uclock.h>
#include <upipe/uref.h>
#include <upipe/uref_block.h>
#include <upipe/uref_block_flow.h>
#include <upipe/uref_clock.h>
#include <upipe/upump.h>
#include <upipe/upipe.h>
#include <upipe/upipe_helper_upipe.h>
#include <upipe/upipe_helper_urefcount.h>
#include <upipe/upipe_helper_void.h>
#include <upipe/upipe_helper_uref_mgr.h>
#include <upipe/upipe_helper_ubuf_mgr.h>
#include <upipe/upipe_helper_output.h>
#include <upipe/upipe_helper_upump_mgr.h>
#include <upipe/upipe_helper_upump.h>
#include <upipe/upipe_helper_uclock.h>
#include <upipe/upipe_helper_output_size.h>
#include <upipe-modules/upipe_fi_source.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <netdb.h>
#include <assert.h>
#include <sys/socket.h>

#include <rdma/fi_cm.h>

/** default size of buffers when unspecified */
#define UBUF_DEFAULT_SIZE       4096

#define UDP_DEFAULT_TTL 0
#define FI_DEFAULT_PORT 47592

/** @hidden */
static int upipe_fisrc_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a udp socket source pipe. */
struct upipe_fisrc {
    /** refcount management structure */
    struct urefcount urefcount;

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

    /** uclock structure, if not NULL we are in live mode */
    struct uclock *uclock;
    /** uclock request */
    struct urequest uclock_request;

    /** pipe acting as output */
    struct upipe *output;
    /** flow definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    /** upump manager */
    struct upump_mgr *upump_mgr;
    /** read watcher */
    struct upump *upump;
    /** read size */
    unsigned int output_size;


////
    int max_msg_size;
    uint16_t src_port;
    uint16_t dst_port;
    char *dst_addr;

    int transfer_size;

    struct fi_info *fi, *hints;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_ep *ep;
    struct fid_cq *txcq, *rxcq;
    struct fid_mr *mr;
    struct fid_av *av;

    struct fid_mr no_mr;
    uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;

    fi_addr_t remote_fi_addr;
    void *buf, *tx_buf, *rx_buf;
    size_t x_size;


    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_fisrc, upipe, UPIPE_FISRC_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_fisrc, urefcount, upipe_fisrc_free)
UPIPE_HELPER_VOID(upipe_fisrc)

UPIPE_HELPER_OUTPUT(upipe_fisrc, output, flow_def, output_state, request_list)
UPIPE_HELPER_UREF_MGR(upipe_fisrc, uref_mgr, uref_mgr_request,
                      upipe_fisrc_check,
                      upipe_fisrc_register_output_request,
                      upipe_fisrc_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_fisrc, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_fisrc_check,
                      upipe_fisrc_register_output_request,
                      upipe_fisrc_unregister_output_request)
UPIPE_HELPER_UCLOCK(upipe_fisrc, uclock, uclock_request, upipe_fisrc_check,
                    upipe_fisrc_register_output_request,
                    upipe_fisrc_unregister_output_request)

UPIPE_HELPER_UPUMP_MGR(upipe_fisrc, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_fisrc, upump, upump_mgr)
UPIPE_HELPER_OUTPUT_SIZE(upipe_fisrc, output_size)


static int get_cq_comp(struct fid_cq *cq, uint64_t *cur, uint64_t total)
{
    struct fi_cq_err_entry comp;

    do {
        int ret = fi_cq_read (cq, &comp, 1);
        if (ret > 0) {
            (*cur)++;
        } else if (ret == -FI_EAGAIN) {
            continue;
        } else if (ret == -FI_EAVAIL) {
            (*cur)++;
            struct fi_cq_err_entry cq_err = { 0 };

            int ret = fi_cq_readerr (cq, &cq_err, 0);
            if (ret < 0) {
                fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr", ret, fi_strerror(-ret));
                return ret;
            }

            fprintf(stderr, "%s\n", fi_cq_strerror (cq, cq_err.prov_errno,
                        cq_err.err_data, NULL, 0));
            return -cq_err.err;
        } else if (ret < 0) {
            fprintf(stderr, "%s(): ret=%d (%s)\n", "get_cq_comp", ret, fi_strerror(-ret));
            return ret;
        }
    } while (total - *cur > 0);

    return 0;
}

static ssize_t tx(struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    if (get_cq_comp (upipe_fisrc->txcq, &upipe_fisrc->tx_cq_cntr, upipe_fisrc->tx_seq))
        return 1;

    while (fi_send(upipe_fisrc->ep, upipe_fisrc->tx_buf, upipe_fisrc->transfer_size, fi_mr_desc (upipe_fisrc->mr), upipe_fisrc->remote_fi_addr, NULL))
        ;

    upipe_fisrc->tx_seq++;
    return 0;
}

static ssize_t rx (struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    if (get_cq_comp (upipe_fisrc->rxcq, &upipe_fisrc->rx_cq_cntr, upipe_fisrc->rx_seq))
        return 1;

    while (fi_recv(upipe_fisrc->ep, upipe_fisrc->rx_buf, upipe_fisrc->x_size, fi_mr_desc (upipe_fisrc->mr), 0, NULL))
        ;

    upipe_fisrc->rx_seq++;

    return 0;
}

#define RET(cmd)        \
do {                    \
    int ret = cmd;      \
    if (unlikely(ret)) {\
        printf("%s():%d : ret=%d\n", __func__, __LINE__, ret); \
    }                   \
} while (0)

static int alloc_msgs (struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    struct fi_info *fi = upipe_fisrc->fi;
    const unsigned int size_max_power_two = 22;

    upipe_fisrc->x_size = (1 << size_max_power_two) + (1 << (size_max_power_two - 1));
    if (upipe_fisrc->x_size > fi->ep_attr->max_msg_size)
        upipe_fisrc->x_size = fi->ep_attr->max_msg_size;
    size_t buf_size = upipe_fisrc->x_size * 2;

    assert(upipe_fisrc->x_size >= upipe_fisrc->transfer_size);
    ////////////////

    errno = 0;
    long alignment = sysconf (_SC_PAGESIZE);
    if (alignment <= 0)
        return 1;

    /* Extra alignment for the second part of the buffer */
    buf_size += alignment;

    RET(posix_memalign (&upipe_fisrc->buf, (size_t) alignment, buf_size));
    memset (upipe_fisrc->buf, 0, buf_size);
    upipe_fisrc->rx_buf = upipe_fisrc->buf;
    upipe_fisrc->tx_buf = (char *) upipe_fisrc->buf + upipe_fisrc->x_size;
    upipe_fisrc->tx_buf =
        (void *) (((uintptr_t) upipe_fisrc->tx_buf + alignment - 1) & ~(alignment - 1));

    if (fi->domain_attr->mr_mode & FI_MR_LOCAL)
        RET(fi_mr_reg (upipe_fisrc->domain, upipe_fisrc->buf, buf_size,
                FI_SEND | FI_RECV, 0, 0, 0, &upipe_fisrc->mr, NULL));

    upipe_fisrc->mr = &upipe_fisrc->no_mr;
    return 0;
}

static int alloc_active_res (struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    struct fi_info *fi = upipe_fisrc->fi;
    RET(alloc_msgs (upipe));

    static struct fi_cq_attr cq_attr;
    if (cq_attr.format == FI_CQ_FORMAT_UNSPEC)
        cq_attr.format = FI_CQ_FORMAT_CONTEXT;

    cq_attr.wait_obj = FI_WAIT_NONE;

    cq_attr.size = fi->tx_attr->size;
    RET(fi_cq_open (upipe_fisrc->domain, &cq_attr, &upipe_fisrc->txcq, &upipe_fisrc->txcq));

    cq_attr.size = fi->rx_attr->size;
    RET(fi_cq_open (upipe_fisrc->domain, &cq_attr, &upipe_fisrc->rxcq, &upipe_fisrc->rxcq));

    struct fi_av_attr av_attr = {0};
    if (fi->ep_attr->type == FI_EP_RDM || fi->ep_attr->type == FI_EP_DGRAM) {
        if (fi->domain_attr->av_type != FI_AV_UNSPEC)
            av_attr.type = fi->domain_attr->av_type;

        RET(fi_av_open (upipe_fisrc->domain, &av_attr, &upipe_fisrc->av, NULL));
    }

    RET(fi_endpoint (upipe_fisrc->domain, fi, &upipe_fisrc->ep, NULL));

    return 0;
}

/** @internal @This allocates a udp socket source pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_fisrc_alloc(struct upipe_mgr *mgr,
                                        struct uprobe *uprobe,
                                        uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_fisrc_alloc_void(mgr, uprobe, signature, args);
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    upipe_fisrc_init_urefcount(upipe);
    upipe_fisrc_init_uref_mgr(upipe);
    upipe_fisrc_init_ubuf_mgr(upipe);
    upipe_fisrc_init_output(upipe);
    upipe_fisrc_init_upump_mgr(upipe);
    upipe_fisrc_init_upump(upipe);
    upipe_fisrc_init_uclock(upipe);
    upipe_fisrc_init_output_size(upipe, UBUF_DEFAULT_SIZE);

    upipe_fisrc->max_msg_size = 0;
    upipe_fisrc->transfer_size = 64;

    upipe_fisrc->src_port = FI_DEFAULT_PORT+1;
    upipe_fisrc->dst_port = FI_DEFAULT_PORT;

    upipe_fisrc->max_msg_size = upipe_fisrc->transfer_size = 1024;

    upipe_fisrc->hints = fi_allocinfo();
    if (!upipe_fisrc->hints) {
    }

    upipe_fisrc->hints->ep_attr->type = FI_EP_DGRAM;
    upipe_fisrc->hints->caps = FI_MSG;
    upipe_fisrc->hints->mode = FI_CONTEXT;
    upipe_fisrc->hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;

    upipe_fisrc->hints->addr_format = AF_INET;
    upipe_fisrc->hints->dest_addrlen = sizeof(struct sockaddr_in);
    upipe_fisrc->hints->dest_addr = calloc (1, upipe_fisrc->hints->dest_addrlen);
    upipe_fisrc->hints->src_addrlen = sizeof(struct sockaddr_in);
    upipe_fisrc->hints->src_addr = calloc (1, upipe_fisrc->hints->src_addrlen);
    struct sockaddr_in *s = upipe_fisrc->hints->src_addr;
    *s = (struct sockaddr_in) {
        .sin_family = AF_INET,
        .sin_port = htons(upipe_fisrc->src_port),
        .sin_addr = {
            .s_addr = htonl(INADDR_LOOPBACK),
        },
    };
    struct sockaddr_in *d = upipe_fisrc->hints->dest_addr;
    *d = *s;
    d->sin_port = htons(upipe_fisrc->dst_port);

//#define RET(x) x
    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            NULL, NULL, 0, upipe_fisrc->hints, &upipe_fisrc->fi));

    RET(fi_fabric (upipe_fisrc->fi->fabric_attr, &upipe_fisrc->fabric, NULL));
    RET(fi_domain (upipe_fisrc->fabric, upipe_fisrc->fi, &upipe_fisrc->domain, NULL));
    RET(alloc_active_res (upipe));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->av->fid, 0));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->txcq->fid, FI_TRANSMIT));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->rxcq->fid, FI_RECV));

    RET(fi_enable (upipe_fisrc->ep));
    RET(rx(upipe));

    fi_av_insert(upipe_fisrc->av, upipe_fisrc->hints->dest_addr, 1, &upipe_fisrc->remote_fi_addr, 0, NULL);

    if (upipe_fisrc->hints->ep_attr->type == FI_EP_DGRAM) {
        if (upipe_fisrc->max_msg_size)
            upipe_fisrc->hints->ep_attr->max_msg_size = upipe_fisrc->max_msg_size;
        /* Post an extra receive to avoid lacking a posted receive in the finalize.  */
        if (fi_recv (upipe_fisrc->ep, upipe_fisrc->rx_buf, upipe_fisrc->x_size, fi_mr_desc (upipe_fisrc->mr), 0, NULL)) {
            //return 1;
        }
    }

    upipe_throw_ready(upipe);
    return upipe;
}

/** @internal @This reads data from the source and outputs it.
 * It is called either when the idler triggers (permanent storage mode) or
 * when data is available on the udp socket descriptor (live stream mode).
 *
 * @param upump description structure of the read watcher
 */
static void upipe_fisrc_worker(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    uint64_t systime = 0; /* to keep gcc quiet */
    if (unlikely(upipe_fisrc->uclock != NULL))
        systime = uclock_now(upipe_fisrc->uclock);

    struct uref *uref = uref_block_alloc(upipe_fisrc->uref_mgr,
                                         upipe_fisrc->ubuf_mgr,
                                         upipe_fisrc->output_size);
    if (unlikely(uref == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return;
    }

    rx(upipe);
    tx(upipe);

    uint8_t *buffer;
    int output_size = -1;
    if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size,
                                               &buffer)))) {
        uref_free(uref);
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return;
    }
    assert(output_size == upipe_fisrc->output_size);

    int ret = -1;

#if 0
    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t ret = recvfrom(upipe_fisrc->fd, buffer, upipe_fisrc->output_size,
                        0, (struct sockaddr*)&addr, &addrlen);
    uref_block_unmap(uref, 0);

    if (unlikely(ret == -1)) {
        uref_free(uref);
        switch (errno) {
            case EINTR:
            case EAGAIN:
#if EAGAIN != EWOULDBLOCK
            case EWOULDBLOCK:
#endif
                /* not an issue, try again later */
                return;
            case EBADF:
            case EINVAL:
            case EIO:
            default:
                break;
        }
        upipe_err_va(upipe, "read error (%m)");
        upipe_fisrc_set_upump(upipe, NULL);
        upipe_throw_source_end(upipe);
        return;
    }
    #endif

    if (unlikely(ret == 0)) {
        uref_free(uref);
        if (likely(upipe_fisrc->uclock == NULL)) {
            upipe_notice_va(upipe, "end of udp socket");
            upipe_fisrc_set_upump(upipe, NULL);
            upipe_throw_source_end(upipe);
        }
        return;
    }
    if (unlikely(upipe_fisrc->uclock != NULL))
        uref_clock_set_cr_sys(uref, systime);
    if (unlikely(ret != upipe_fisrc->output_size))
        uref_block_resize(uref, 0, ret);
    upipe_fisrc_output(upipe, uref, &upipe_fisrc->upump);
}

/** @internal @This checks if the pump may be allocated.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_fisrc_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    if (flow_format != NULL)
        upipe_fisrc_store_flow_def(upipe, flow_format);

    upipe_fisrc_check_upump_mgr(upipe);
    if (upipe_fisrc->upump_mgr == NULL)
        return UBASE_ERR_NONE;

    if (upipe_fisrc->uref_mgr == NULL) {
        upipe_fisrc_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_fisrc->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_fisrc->uref_mgr, NULL);
        uref_block_flow_set_size(flow_format, upipe_fisrc->output_size);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_fisrc_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    if (upipe_fisrc->uclock == NULL &&
        urequest_get_opaque(&upipe_fisrc->uclock_request, struct upipe *)
            != NULL)
        return UBASE_ERR_NONE;

    if (upipe_fisrc->upump == NULL) {
        struct upump *upump = upump_alloc_timer(upipe_fisrc->upump_mgr,
                                    upipe_fisrc_worker, upipe, upipe->refcount,
                                    0, 1/*UCLOCK_FREQ / 1000*/);
        if (unlikely(upump == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_UPUMP);
            return UBASE_ERR_UPUMP;
        }
        upipe_fisrc_set_upump(upipe, upump);
        upump_start(upump);
    }

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on a udp socket source pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int _upipe_fisrc_control(struct upipe *upipe,
                                 int command, va_list args)
{
    switch (command) {
        case UPIPE_ATTACH_UPUMP_MGR:
            upipe_fisrc_set_upump(upipe, NULL);
            return upipe_fisrc_attach_upump_mgr(upipe);
        case UPIPE_ATTACH_UCLOCK:
            upipe_fisrc_set_upump(upipe, NULL);
            upipe_fisrc_require_uclock(upipe);
            return UBASE_ERR_NONE;

        case UPIPE_GET_FLOW_DEF:
        case UPIPE_GET_OUTPUT:
        case UPIPE_SET_OUTPUT:
            return upipe_fisrc_control_output(upipe, command, args);

        case UPIPE_GET_OUTPUT_SIZE:
        case UPIPE_SET_OUTPUT_SIZE:
            return upipe_fisrc_control_output_size(upipe, command, args);

        case UPIPE_SET_URI: return UBASE_ERR_NONE; // XXXXX

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @internal @This processes control commands on a udp socket source pipe, and
 * checks the status of the pipe afterwards.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_fisrc_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_fisrc_control(upipe, command, args));

    return upipe_fisrc_check(upipe, NULL);
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_fisrc_free(struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

/*
    void *mem_desc[1] = { fi_mr_desc (mr) };
    const char *fin_buf = "fin";
    const size_t fin_buf_size = sizeof (fin_buf);

    strcpy(tx_buf, fin_buf);

    struct iovec iov;
    iov.iov_base = tx_buf;
    iov.iov_len = fin_buf_size;

    struct fi_msg msg = {
        .msg_iov = &iov,
        .iov_count = 1,
        .desc = mem_desc,
        .addr = remote_fi_addr,
    };

    if (fi_sendmsg (ep, &msg, FI_TRANSMIT_COMPLETE))
        return;

    tx_seq++;
*/

    if (upipe_fisrc->upump != NULL)
        upump_stop(upipe_fisrc->upump);

    if (upipe_fisrc->mr != &upipe_fisrc->no_mr)
        fi_close(&upipe_fisrc->mr->fid);
    fi_close(&upipe_fisrc->ep->fid);
    fi_close(&upipe_fisrc->rxcq->fid);
    fi_close(&upipe_fisrc->txcq->fid);
    fi_close(&upipe_fisrc->av->fid);
    fi_close(&upipe_fisrc->domain->fid);
    fi_close(&upipe_fisrc->fabric->fid);

    free (upipe_fisrc->buf);

    fi_freeinfo (upipe_fisrc->fi);
    fi_freeinfo (upipe_fisrc->hints);


    upipe_throw_dead(upipe);

    upipe_fisrc_clean_output_size(upipe);
    upipe_fisrc_clean_uclock(upipe);
    upipe_fisrc_clean_upump(upipe);
    upipe_fisrc_clean_upump_mgr(upipe);
    upipe_fisrc_clean_output(upipe);
    upipe_fisrc_clean_ubuf_mgr(upipe);
    upipe_fisrc_clean_uref_mgr(upipe);
    upipe_fisrc_clean_urefcount(upipe);
    upipe_fisrc_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_fisrc_mgr = {
    .refcount = NULL,
    .signature = UPIPE_FISRC_SIGNATURE,

    .upipe_alloc = upipe_fisrc_alloc,
    .upipe_input = NULL,
    .upipe_control = upipe_fisrc_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all udp socket sources
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_fisrc_mgr_alloc(void)
{
    return &upipe_fisrc_mgr;
}
