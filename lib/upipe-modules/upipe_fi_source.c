/*
 * Copyright (C) 2012-2015 OpenHeadend S.A.R.L.
 * Copyright (C) 2022 Open Broadcast Systems Ltd
 *
 * Authors: Christophe Massiot
 *          Benjamin Cohen
 *          Rafaël Carré
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
#include <upipe/uref_pic.h>
#include <upipe/uref_pic_flow.h>
#include <upipe/uref_pic_flow_formats.h>
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

#include "upipe_udp.h"

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
#include <netinet/in.h>
#include <arpa/inet.h>

#include <rdma/fi_cm.h>

/** default size of buffers when unspecified */
#define UBUF_DEFAULT_SIZE      8961

#define UDP_DEFAULT_TTL 0
#define FI_DEFAULT_PORT 47592

#define MAX_IP_STRING_LENGTH                (64)

/// @brief Maximum EFA device GID length. Contains GID + QPN (see efa_ep_addr).
#define MAX_IPV6_GID_LENGTH                 (32)

/// @brief Maximum IPV6 address string length.
#define MAX_IPV6_ADDRESS_STRING_LENGTH      (64)

/// @brief Maximum connection name string length.
#define CDI_MAX_CONNECTION_NAME_STRING_LENGTH           (128)

/// @brief Maximum stream name string length.
#define CDI_MAX_STREAM_NAME_STRING_LENGTH               (CDI_MAX_CONNECTION_NAME_STRING_LENGTH+10)

/** @hidden */
static int upipe_fisrc_check(struct upipe *upipe, struct uref *flow_format);

typedef enum {
    kProbeStateIdle, // Waiting for ProtocolVersion
    kProbeStateEfaProbe, // Got ProtocolVersion, waiting for probe packets through EFA
    kProbeStateEfaTxProbeAcks, // Received probe packets, sends Connected
    kProbeStateEfaConnected, // Connected
} ProbeState;

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
    struct upump *upump2;

    /** udp socket descriptor */
    int fd;
    /** udp socket uri */
    char *uri;
    /* */
    struct sockaddr_in dst;

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

    uint64_t tx_seq, rx_seq, tx_cq_cntr, rx_cq_cntr;

    fi_addr_t remote_fi_addr;
    void *buf, *tx_buf, *rx_buf;
    size_t x_size;
    size_t nn;

    uint8_t state;

    uint16_t ctrl_packet_num;
    uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
    char senders_ip_str[MAX_IP_STRING_LENGTH+1];

    struct uref *output_uref;

    ProbeState probe_state;
    uint16_t pkt_num;
    char ip[INET6_ADDRSTRLEN];

    uint8_t buffer[5];
    size_t  buffered;

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
UPIPE_HELPER_UPUMP(upipe_fisrc, upump2, upump_mgr)
UPIPE_HELPER_OUTPUT_SIZE(upipe_fisrc, output_size)

typedef enum {
    kProbeCommandReset = 1, ///< Request to reset the connection. Start with 1 so no commands have the value 0.
    kProbeCommandPing,      ///< Request to ping the connection.
    kProbeCommandConnected, ///< Notification that connection has been established (probe has completed).
    kProbeCommandAck,       ///< Packet is an ACK response to a previously sent command.
    kProbeCommandProtocolVersion, ///< Packet contains protocol version of sender.
} ProbeCommand;

static const char *get_cmd(ProbeCommand cmd)
{
    static const char *foo[] = {
        [kProbeCommandReset] = "Reset",
        [kProbeCommandPing] = "Ping",
        [kProbeCommandConnected] = "Connected",
        [kProbeCommandAck] = "Ack",
        [kProbeCommandProtocolVersion] = "ProtocolVersion",
    };

    if (cmd < kProbeCommandReset || cmd > kProbeCommandProtocolVersion)
        return "?";

    return foo[cmd];
}

static void put_32le(uint8_t *buf, const uint32_t val)
{
    for (int i = 0; i < 4; i++)
        buf[i] = (val >> 8*i) & 0xff;
}

static uint32_t get_32le(const uint8_t *buf)
{
    uint32_t val = 0;
    for (int i = 0; i < 4; i++)
        val |= buf[i] << i*8;
    return val;
}

static uint64_t get_64le(const uint8_t *buf)
{
    uint64_t val = 0;
    for (int i = 0; i < 8; i++)
        val |= buf[i] << i*8;
    return val;
}

static void put_16le(uint8_t *buf, const uint16_t val)
{
    *buf++ = val & 0xff;
    *buf++ = val >> 8;
}

static uint16_t get_16le(const uint8_t *buf)
{
    uint16_t val = *buf++;
    val |= *buf << 8;
    return val;
}

/**
 * @brief Calculate a checksum and return it.
 *
 * @param buffer_ptr Pointer to data to calculate checksum.
 * @param size Size of buffer in bytes.
 *
 * @return Calculated checksum value.
 */
static uint16_t CalculateChecksum(const uint8_t *buf, int size, const uint8_t *csum_pos)
{
    uint32_t cksum = 0;

    // Sum entire packet.
    while (size > 1) {
        uint16_t word = get_16le(buf);
        if (csum_pos) { /* zero checksum when verifying */
            if (csum_pos == buf+1)
                word &= 0x00ff;
            else if (csum_pos == buf-1)
                word &= 0xff00;
            else if (csum_pos == buf) /* should not happen */ {
                word = 0;
                abort();
            }
        }
        cksum += word;
        buf += 2;
        size -= 2;
    }

    // Pad to 16-bit boundary if necessary.
    if (size == 1) {
        cksum += *buf;
    }

    // Add carries and do one's complement.
    cksum = (cksum >> 16) + (cksum & 0xffff);
    cksum += (cksum >> 16);
    return (uint16_t)(~cksum);
}

static void upipe_fisrc_parse_cmd(struct upipe *upipe, const uint8_t *buf, size_t n, ProbeCommand *command)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    const uint8_t *orig_buf = buf;
    assert(n > 100);

    uint8_t v     = buf[0]; ///< CDI protocol version number.
    uint8_t major = buf[1]; ///< CDI protocol major version number.
    uint8_t probe = buf[2]; ///< CDI probe version number.

    buf += 3;
    n -= 3;

    *command = get_32le(buf);
    buf += 4;
    n -= 4;

    memcpy(upipe_fisrc->senders_ip_str, buf, MAX_IP_STRING_LENGTH);
    upipe_fisrc->senders_ip_str[MAX_IP_STRING_LENGTH] = '\0';
    buf += MAX_IP_STRING_LENGTH;
    n -= MAX_IP_STRING_LENGTH;

    inet_aton(upipe_fisrc->senders_ip_str, &upipe_fisrc->dst.sin_addr);

    memcpy(upipe_fisrc->senders_gid_array, buf, MAX_IPV6_GID_LENGTH);
    buf += MAX_IPV6_GID_LENGTH;
    n -= MAX_IPV6_GID_LENGTH;

    char senders_stream_name_str[CDI_MAX_STREAM_NAME_STRING_LENGTH+1];
    memcpy(senders_stream_name_str, buf, sizeof(senders_stream_name_str));
    senders_stream_name_str[CDI_MAX_STREAM_NAME_STRING_LENGTH] = '\0';
    buf += CDI_MAX_STREAM_NAME_STRING_LENGTH;
    n -= CDI_MAX_STREAM_NAME_STRING_LENGTH;

    if (v == 1) {
        // senders_stream_identifier
        buf += 4; // 32 bits
        n -= 4;
    }

    uint16_t senders_control_dest_port = get_16le(buf);
    buf += 2;
    n -= 2;

    upipe_fisrc->dst.sin_port = htons(senders_control_dest_port);

    upipe_fisrc->pkt_num = get_16le(buf);
    buf += 2;
    n -= 2;

    const uint8_t *csum_pos = buf;
    uint16_t csum = get_16le(buf);
    buf += 2;
    n -= 2;

    if (*command == kProbeCommandAck) {
        uint8_t ack_command = get_32le(buf);
        buf += 4;
        n -= 4;
        uint16_t ack_control_packet_num = get_16le(buf);
        buf += 2;
        n -= 2;

        upipe_dbg_va(upipe, "ack cmd: %d - num %d\n", ack_command, ack_control_packet_num);
    } else {
        bool requires_ack = buf[0];
        (void)requires_ack;
        buf += 1;
        n -= 1;
    }

    uint16_t checksum = CalculateChecksum(orig_buf, buf - orig_buf, csum_pos);
    if (csum != checksum) {
        upipe_err_va(upipe, "bad checksum 0x%.4x != 0x%.4x", csum, checksum);
    }

    upipe_dbg_va(upipe, "v%u.%u.%u %s senders ip %s - stream name %s - ctrl dst port %hu - pkt num %hu",
            v, major, probe, get_cmd(*command),
        upipe_fisrc->senders_ip_str, senders_stream_name_str, senders_control_dest_port, upipe_fisrc->pkt_num);
}

static int get_cq_comp(struct fid_cq *cq, uint64_t *cur, uint64_t total)
{
    struct fi_cq_data_entry comp;

    int z = 0;
    do {
        int ret = fi_cq_read (cq, &comp, 1);
        if (ret > 0) {
            if (ret != 1)
                printf("cq_read %d\n", ret);
            (*cur)++;
        } else if (ret == -FI_EAGAIN) {
            if (z++ > 10)
                return 1;
            continue;
        } else if (ret == -FI_EAVAIL) {
            (*cur)++;
            struct fi_cq_err_entry cq_err = { 0 };

            int ret = fi_cq_readerr (cq, &cq_err, 0);
            if (ret < 0) {
                fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr", ret, fi_strerror(-ret));
                return ret;
            }

            fprintf(stderr, "X %s\n", fi_cq_strerror (cq, cq_err.prov_errno,
                        cq_err.err_data, NULL, 0));
            exit(1);
            return -cq_err.err;
        } else if (ret < 0) {
            fprintf(stderr, "%s(): ret=%d (%s)\n", "get_cq_comp", ret, fi_strerror(-ret));
            return ret;
        }
    } while (total - *cur > 0);

    return 0;
}

static ssize_t rx (struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

    if (get_cq_comp (upipe_fisrc->rxcq, &upipe_fisrc->rx_cq_cntr, upipe_fisrc->rx_seq))
        return -1;

    struct iovec msg_iov = {
        .iov_base = (uint8_t*)upipe_fisrc->rx_buf + ++upipe_fisrc->nn * 8961,
        .iov_len = 8961,
    };

    if (upipe_fisrc->nn >= upipe_fisrc->x_size / 8961)
        upipe_fisrc->nn = 0;

    struct fi_msg msg = {
        .msg_iov = &msg_iov,
        .desc = fi_mr_desc (upipe_fisrc->mr),
        .iov_count = 1,
        .addr = 0,
        .context = NULL,
        .data = 0,
    };

    ssize_t s = fi_recvmsg(upipe_fisrc->ep, &msg, 0);
    if (!s)
        upipe_fisrc->rx_seq++;
    else {
        upipe_err(upipe, "fi_recvmsg");
    }

    return msg_iov.iov_len;
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
    upipe_fisrc->nn = 0;
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

    RET(fi_mr_reg (upipe_fisrc->domain, upipe_fisrc->buf, buf_size,
            FI_SEND | FI_RECV | FI_MULTI_RECV, 0, 0, 0, &upipe_fisrc->mr, NULL));

    return 0;
}

static int alloc_active_res (struct upipe *upipe)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    struct fi_info *fi = upipe_fisrc->fi;
    RET(alloc_msgs (upipe));

    struct fi_cq_attr cq_attr = {
        .wait_obj = FI_WAIT_NONE,
        .format = FI_CQ_FORMAT_DATA
    };

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
    upipe_fisrc_init_upump2(upipe);
    upipe_fisrc_init_uclock(upipe);
    upipe_fisrc_init_output_size(upipe, UBUF_DEFAULT_SIZE);

    upipe_fisrc->rx_seq = 0;
    upipe_fisrc->rx_cq_cntr = 0;
    upipe_fisrc->output_uref = NULL;

    upipe_fisrc->max_msg_size = 0;

    upipe_fisrc->src_port = FI_DEFAULT_PORT+1;
    upipe_fisrc->dst_port = FI_DEFAULT_PORT;

    upipe_fisrc->max_msg_size = upipe_fisrc->transfer_size = 8961;
    upipe_fisrc->ctrl_packet_num = 0;

    upipe_fisrc->hints = fi_allocinfo();
    if (!upipe_fisrc->hints) {
    }

    upipe_fisrc->hints->ep_attr->type = FI_EP_DGRAM;

    upipe_fisrc->hints->caps = FI_MSG;
    upipe_fisrc->hints->mode = FI_CONTEXT;
    upipe_fisrc->hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;

    upipe_fisrc->hints->fabric_attr->prov_name = (char*)"sockets";
    upipe_fisrc->hints->ep_attr->type = FI_EP_RDM;
    upipe_fisrc->hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    upipe_fisrc->hints->domain_attr->threading = FI_THREAD_DOMAIN;
    upipe_fisrc->hints->tx_attr->comp_order = FI_ORDER_NONE;
    upipe_fisrc->hints->rx_attr->comp_order = FI_ORDER_NONE;

    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            NULL, NULL, 0, upipe_fisrc->hints, &upipe_fisrc->fi));

    RET(fi_fabric (upipe_fisrc->fi->fabric_attr, &upipe_fisrc->fabric, NULL));
    RET(fi_domain (upipe_fisrc->fabric, upipe_fisrc->fi, &upipe_fisrc->domain, NULL));
    RET(alloc_active_res (upipe));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->av->fid, 0));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->txcq->fid, FI_TRANSMIT));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->rxcq->fid, FI_RECV));

    RET(fi_enable (upipe_fisrc->ep));
    rx(upipe);

    if (upipe_fisrc->hints->ep_attr->type == FI_EP_DGRAM) {
        if (upipe_fisrc->max_msg_size)
            upipe_fisrc->hints->ep_attr->max_msg_size = upipe_fisrc->max_msg_size;
        /* Post an extra receive to avoid lacking a posted receive in the finalize.  */
        if (fi_recv (upipe_fisrc->ep, upipe_fisrc->rx_buf, upipe_fisrc->x_size, fi_mr_desc (upipe_fisrc->mr), 0, NULL)) {
            //return 1;
        }
    }

    upipe_fisrc->fd = -1;
    upipe_fisrc->uri = NULL;
    upipe_fisrc->dst.sin_family = AF_INET;

    upipe_fisrc->probe_state = kProbeStateIdle;
    upipe_fisrc->pkt_num = 0;
    upipe_fisrc->ip[0] = '\0';
    upipe_fisrc->buffered = 0;

    upipe_throw_ready(upipe);
    return upipe;
}

static void transmit(struct upipe *upipe, ProbeCommand cmd, bool requires_ack, ProbeCommand reply)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

    uint8_t *tx_buf = upipe_fisrc->tx_buf;
    memset(tx_buf, 0, 300);
    uint8_t *buf = tx_buf;

    // senders_version
    *buf++ = 2;
    *buf++ = 1;
    *buf++ = 4;

    // ProbeCommand
    put_32le(buf, cmd);
    buf += 4;

    // senders_ip_str
    strncpy((char*)buf, upipe_fisrc->ip, MAX_IP_STRING_LENGTH - 1);
    buf[MAX_IP_STRING_LENGTH - 1] = '\0';

    buf += MAX_IP_STRING_LENGTH;

    // senders_gid_array
    uint8_t ipv6_gid[MAX_IPV6_GID_LENGTH];

    size_t name_length = MAX_IPV6_GID_LENGTH;

    int ret = fi_getname(&upipe_fisrc->ep->fid, (void*)ipv6_gid, &name_length);
    if (ret) {
        upipe_err(upipe, "CRAP");
    } else {
        memset(buf, 0, MAX_IPV6_GID_LENGTH);
        memcpy(buf, ipv6_gid, name_length);
    }

    buf += MAX_IPV6_GID_LENGTH;

    // senders_stream_name_str
    buf += CDI_MAX_STREAM_NAME_STRING_LENGTH;

    // senders_control_dest_port
    uint16_t port = 47593; // TODO
    put_16le(buf, port);
    buf += 2;

    // control_packet_num
    put_16le(buf, upipe_fisrc->ctrl_packet_num++);
    buf += 2;

    // checksum
    uint8_t *csum = buf; /* written later */
    put_16le(buf, 0);
    buf += 2;

    if (cmd == kProbeCommandAck) {
        // ack_command
        put_32le(buf, reply);
        buf += 4;

        // ack_control_packet_num
        put_16le(buf, upipe_fisrc->pkt_num);
        buf += 2;
    } else {
        // requires_ack
        *buf++ = !!requires_ack;
    }

    size_t n = buf - tx_buf;

    uint16_t checksum = CalculateChecksum(tx_buf, n, NULL);

    put_16le(csum, checksum);
    ssize_t ss = sendto(upipe_fisrc->fd, tx_buf, n, 0, (struct sockaddr*)&upipe_fisrc->dst, sizeof(upipe_fisrc->dst));
    if (ss < 0)
        perror("sendto");
}

typedef enum {
    kPayloadTypeData = 0,   ///< Payload contains application payload data.
    kPayloadTypeDataOffset, ///< Payload contains application payload data with data offset field in each packet.
    kPayloadTypeProbe,      ///< Payload contains probe data.
    kPayloadTypeKeepAlive,  ///< Payload is being used for keeping the connection alive (don't use app payload
                            ///  callbacks).
} CdiPayloadType;

static const char *get_pt(int pt)
{
    static const char *foo[] = {
        [kPayloadTypeData] = "Data",
        [kPayloadTypeDataOffset] = "DataOffset",
        [kPayloadTypeProbe] = "Probe",
        [kPayloadTypeKeepAlive] = "KeepAlive",
    };

    if (pt < kPayloadTypeData || pt > kPayloadTypeKeepAlive)
        return "?";

    return foo[pt];
}

/** @internal @This reads data from the source and outputs it.
 * It is called either when the idler triggers (permanent storage mode) or
 * when data is available on the udp socket descriptor (live stream mode).
 *
 * @param upump description structure of the read watcher
 */
static void upipe_fisrc_worker2(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    uint64_t systime = 0; /* to keep gcc quiet */
    if (unlikely(upipe_fisrc->uclock != NULL))
        systime = uclock_now(upipe_fisrc->uclock);
    struct uref *uref = upipe_fisrc->output_uref;

    if (unlikely(uref == NULL)) {
        uref = uref_pic_alloc(upipe_fisrc->uref_mgr, upipe_fisrc->ubuf_mgr, 1920, 1080);
        if (unlikely(uref == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            upipe_err(upipe, "FATAL");
            return;
        }
        upipe_fisrc->output_uref = uref;
        uref_clock_set_cr_sys(uref, systime);
        uref_clock_set_pts_prog(uref, systime);
        upipe_throw_clock_ref(upipe, uref, systime, 0);
        upipe_throw_clock_ts(upipe, uref);
    }

    uint16_t *y, *u, *v;
    if (!ubase_check(uref_pic_plane_write(uref, "y10l", 0, 0, -1, -1, (uint8_t**)&y))) {
        upipe_err(upipe, "Cannot map y");
    }
    if (!ubase_check(uref_pic_plane_write(uref, "u10l", 0, 0, -1, -1, (uint8_t**)&u))) {
        upipe_err(upipe, "Cannot map u");
    }
    if (!ubase_check(uref_pic_plane_write(uref, "v10l", 0, 0, -1, -1, (uint8_t**)&v))) {
        upipe_err(upipe, "Cannot map v");
    }

    uint8_t *buffer = upipe_fisrc->rx_buf;
    buffer += upipe_fisrc->nn * 8961; // something to do with jumbo
    ssize_t s = rx(upipe);

    size_t offset = 0;
    if (s <= 0)
        goto skip;

    assert(s >= 9);
    assert(s == 8961);

    uint8_t pt = buffer[0];
    uint16_t seq = get_16le(&buffer[1]);
    uint16_t num = get_16le(&buffer[3]);
    uint32_t id = get_32le(&buffer[5]);
    if (pt != kPayloadTypeDataOffset && pt != kPayloadTypeProbe && pt != kPayloadTypeData)
        upipe_dbg_va(upipe, "PT %s(%d) - seq %d num %d id %d", get_pt(pt), pt, seq, num, id);

    buffer += 9;
    s -= 9;

    switch(pt) {
    case kPayloadTypeData:
        if (seq == 0) {
            assert(s >= 4+8+8+8+2+8);
            uint32_t total_payload_size = get_32le(buffer); buffer += 4;
            uint64_t max_latency_microsecs = get_64le(buffer); buffer += 8;
            uint32_t sec = get_32le(buffer); buffer += 4; /// The number of seconds since the SMPTE Epoch which is 1970-01-01T00:00:00.
            uint32_t nsec = get_32le(buffer); buffer += 4; /// The number of fractional seconds as measured in nanoseconds. The value in this field is always less than 10^9.
            uint64_t payload_user_data = get_64le(buffer); buffer += 8;

            uint16_t  extra_data_size = get_16le(buffer); buffer += 2;
            uint64_t tx_start_time_microseconds = get_64le(buffer); buffer += 8;
            upipe_dbg_va(upipe,
                    "total payload size %u max latency usecs %" PRId64 " PTP %u.%09u userdata %" PRIx64 " extradata %d tx_start_time_usec %" PRId64,

                    total_payload_size,
                    max_latency_microsecs,
                    sec,
                    nsec,
                    payload_user_data,
                    extra_data_size,
                    tx_start_time_microseconds);

            s -= 4+8+8+8+2+8;

            // TODO: this is flow def
            assert (s >= extra_data_size);
            s -= extra_data_size;
            char foo[extra_data_size+1];
            memcpy(foo, buffer, extra_data_size);
            foo[extra_data_size] = '\0';
            if (extra_data_size >= 259) {
                printf("XTRA %s\n", &foo[2]);
                printf("XTRA2 %s\n", &foo[259]);
            }
            buffer += extra_data_size;
        }
        break;

    case kPayloadTypeDataOffset:
        assert(s >= 4);
        offset = get_32le(buffer);
        buffer += 4; s -= 4;
        break;
    case kPayloadTypeKeepAlive:
        break;
    case kPayloadTypeProbe:
        if (upipe_fisrc->probe_state == kProbeStateEfaProbe) {
            /* Don't wait for an arbitrary number of packets (EFA_PROBE_PACKET_COUNT) */
            upipe_fisrc->probe_state = kProbeStateEfaTxProbeAcks;
            transmit(upipe, kProbeCommandConnected, false, 0);
        }

        s = 0;
    default: break;
    }

    offset -= (offset % 5);

    if (offset + upipe_fisrc->buffered + s > 5184000) {
        if (offset + upipe_fisrc->buffered + s > 5184000 + 8191)
        upipe_err_va(upipe, "OVERFLOW offset %zu, s %zu buffered %zu", offset, s, upipe_fisrc->buffered);
        s = 5184000 - offset - upipe_fisrc->buffered;
    }


    if (0 && s) {
        bool c = false;
        static int x;
        static FILE *f;
        if (!f) {
            f = fopen("/home/fun/dump.c", "w");
            assert(f);
        }
        if (c)
            fprintf(f, "pkt_%d[%zu] = {\n", x++, s);

        int m = 0;
        for (unsigned i = 0; i < s; i++) {
            if (c)
                fprintf(f, "0x%.2x, ", buffer[i]);
            else
                fputc(buffer[i], f);
            if (c && ++m && (i & 15) == 15) {
                fprintf(f, "\n");
                m = 0;
            }
        }
        if (c) {
            if (m)
                fprintf(f, "\n");

            fprintf(f, "};\n");
        }
        fflush(f);
    }

    uint8_t *src = buffer;
    int i = offset / 5 * 2;

    if (upipe_fisrc->buffered && s >= 5 - upipe_fisrc->buffered) {
        memcpy(&upipe_fisrc->buffer[upipe_fisrc->buffered], src, 5 - upipe_fisrc->buffered);
        src += 5 - upipe_fisrc->buffered;

        uint8_t a = upipe_fisrc->buffer[0];
        uint8_t b = upipe_fisrc->buffer[1];
        uint8_t c = upipe_fisrc->buffer[2];
        uint8_t d = upipe_fisrc->buffer[3];
        uint8_t e = upipe_fisrc->buffer[4];
        u[i/2] = (a << 2)          | ((b >> 6) & 0x03); //1111111122
        y[i+0] = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
        v[i/2] = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
        y[i+1] = ((d & 0x03) << 8) | e;                 //4455555555

        i += 2;
        s -= 5 - upipe_fisrc->buffered;
        offset += 5;
    }

    while (s >= 5) {
        uint8_t a = *src++;
        uint8_t b = *src++;
        uint8_t c = *src++;
        uint8_t d = *src++;
        uint8_t e = *src++;
        u[i/2] = (a << 2)          | ((b >> 6) & 0x03); //1111111122
        y[i+0] = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
        v[i/2] = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
        y[i+1] = ((d & 0x03) << 8) | e;                 //4455555555

        i += 2;
        s -= 5;
        offset += 5;
    }

    upipe_fisrc->buffered = s;
    if (s)
        memcpy(upipe_fisrc->buffer, src, s);

skip:

    uref_pic_plane_unmap(uref, "y10l", 0, 0, -1, -1);
    uref_pic_plane_unmap(uref, "u10l", 0, 0, -1, -1);
    uref_pic_plane_unmap(uref, "v10l", 0, 0, -1, -1);

    if (offset >= 5184000) {
        if (offset > 5184000)
            upipe_err_va(upipe, "%zu too big", offset - 5184000);
        offset = 0;
        upipe_fisrc->buffered = 0;
        upipe_fisrc->output_uref = NULL;
        upipe_fisrc_output(upipe, uref, &upipe_fisrc->upump);
    }
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

    uint8_t buffer[1500];

    struct sockaddr_storage addr;
    socklen_t addrlen = sizeof(addr);

    ssize_t ret = recvfrom(upipe_fisrc->fd, buffer, sizeof(buffer),
           0, (struct sockaddr*)&addr, &addrlen);

    if (addr.ss_family == AF_INET || addr.ss_family == AF_INET6) {
        struct sockaddr_in *s = (struct sockaddr_in*)&addr;
        struct sockaddr_in6 *s6 = (struct sockaddr_in6*)&addr;
        void *src = addr.ss_family == AF_INET ? (void*)&s->sin_addr : (void*)&s6->sin6_addr;
        if (inet_ntop(addr.ss_family, src, upipe_fisrc->ip, sizeof(upipe_fisrc->ip)))
            upipe_fisrc->ip[0] = '\0';
    }

    if (unlikely(ret == -1)) {
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

    if (unlikely(ret == 0)) {
        if (likely(upipe_fisrc->uclock == NULL)) {
            upipe_notice_va(upipe, "end of udp socket");
            upipe_fisrc_set_upump(upipe, NULL);
            upipe_throw_source_end(upipe);
        }
        return;
    }

    ProbeCommand cmd;
    upipe_fisrc_parse_cmd(upipe, buffer, ret, &cmd);

    transmit(upipe, kProbeCommandAck, false, cmd);
    if (cmd == kProbeCommandProtocolVersion)
        upipe_fisrc->probe_state = kProbeStateEfaProbe;
    if (cmd == kProbeCommandPing)
        upipe_fisrc->probe_state = kProbeStateEfaConnected;
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
        struct uref *flow_format = uref_pic_flow_alloc_yuv422p10le(upipe_fisrc->uref_mgr);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        UBASE_RETURN(uref_pic_flow_set_hsize(flow_format, 1920));
        UBASE_RETURN(uref_pic_flow_set_vsize(flow_format, 1080));
        struct urational fps = { 10, 1 };
        UBASE_RETURN(uref_pic_flow_set_fps(flow_format, fps));

        upipe_fisrc_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    if (upipe_fisrc->uclock == NULL &&
        urequest_get_opaque(&upipe_fisrc->uclock_request, struct upipe *)
            != NULL)
        return UBASE_ERR_NONE;

    if (upipe_fisrc->upump == NULL) {
        struct upump *upump = upump_alloc_fd_read(upipe_fisrc->upump_mgr,
                                    upipe_fisrc_worker, upipe, upipe->refcount,
                                    upipe_fisrc->fd);

        if (unlikely(upump == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_UPUMP);
            return UBASE_ERR_UPUMP;
        }
        upipe_fisrc_set_upump(upipe, upump);
        upump_start(upump);
    }

    if (upipe_fisrc->upump2 == NULL) {
        struct upump *upump = upump_alloc_timer(upipe_fisrc->upump_mgr,
                upipe_fisrc_worker2, upipe, upipe->refcount,
                0, UCLOCK_FREQ / 1000);

        if (unlikely(upump == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_UPUMP);
            return UBASE_ERR_UPUMP;
        }
        upipe_fisrc_set_upump2(upipe, upump);
        upump_start(upump);
    }
    return UBASE_ERR_NONE;
}

/** @internal @This returns the uri of the currently opened udp socket.
 *
 * @param upipe description structure of the pipe
 * @param uri_p filled in with the uri of the udp socket
 * @return an error code
 */
static int upipe_fisrc_get_uri(struct upipe *upipe, const char **uri_p)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);
    assert(uri_p != NULL);
    *uri_p = upipe_fisrc->uri;
    return UBASE_ERR_NONE;
}

/** @internal @This asks to open the given udp socket.
 *
 * @param upipe description structure of the pipe
 * @param uri relative or absolute uri of the udp socket
 * @return an error code
 */
static int upipe_fisrc_set_uri(struct upipe *upipe, const char *uri)
{
    bool use_tcp = 0;
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

    if (unlikely(upipe_fisrc->fd != -1)) {
        if (likely(upipe_fisrc->uri != NULL)) {
            upipe_notice_va(upipe, "closing udp socket %s", upipe_fisrc->uri);
        }
        ubase_clean_fd(&upipe_fisrc->fd);
    }
    ubase_clean_str(&upipe_fisrc->uri);
    upipe_fisrc_set_upump(upipe, NULL);

    if (unlikely(uri == NULL))
        return UBASE_ERR_NONE;

    upipe_fisrc->fd = upipe_udp_open_socket(upipe, uri,
            UDP_DEFAULT_TTL, FI_DEFAULT_PORT, 0, NULL, &use_tcp, NULL, NULL);
    if (unlikely(upipe_fisrc->fd == -1)) {
        upipe_err_va(upipe, "can't open udp socket %s (%m)", uri);
        return UBASE_ERR_EXTERNAL;
    }

    upipe_fisrc->uri = strdup(uri);
    if (unlikely(upipe_fisrc->uri == NULL)) {
        ubase_clean_fd(&upipe_fisrc->fd);
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return UBASE_ERR_ALLOC;
    }
    upipe_notice_va(upipe, "opening udp socket %s", upipe_fisrc->uri);
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

        case UPIPE_GET_URI: {
            const char **uri_p = va_arg(args, const char **);
            return upipe_fisrc_get_uri(upipe, uri_p);
        }
        case UPIPE_SET_URI: {
            const char *uri = va_arg(args, const char *);
            return upipe_fisrc_set_uri(upipe, uri);
        }

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

    fi_close(&upipe_fisrc->mr->fid);
    fi_close(&upipe_fisrc->ep->fid);
    fi_close(&upipe_fisrc->rxcq->fid);
    fi_close(&upipe_fisrc->txcq->fid);
    fi_close(&upipe_fisrc->av->fid);
    fi_close(&upipe_fisrc->domain->fid);
    fi_close(&upipe_fisrc->fabric->fid);

    free (upipe_fisrc->buf);

    fi_freeinfo (upipe_fisrc->fi);
//    fi_freeinfo (upipe_fisrc->hints); // FIXME

    upipe_throw_dead(upipe);

    upipe_fisrc_clean_output_size(upipe);
    upipe_fisrc_clean_uclock(upipe);
    upipe_fisrc_clean_upump2(upipe);
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
