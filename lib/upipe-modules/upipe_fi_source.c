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
#include <upipe/uref_dump.h>
#include <upipe/udict.h>
#include <upipe/ustring.h>
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

#include <sys/mman.h>

#include <rdma/fi_cm.h>

/** default size of buffers when unspecified */
#define UBUF_DEFAULT_SIZE      8864
#define UBUF_DEFAULT_SIZE_A    8864

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
    uint16_t dst_port;
    char *dst_addr;

    int transfer_size;

    struct fi_info *fi;
    struct fid_fabric *fabric;
    struct fid_domain *domain;
    struct fid_ep *ep;
    struct fid_cq *rxcq;
    struct fid_mr *mr;
    struct fid_av *av;

    uint64_t rx_seq, rx_cq_cntr;

    void *buf, *rx_buf;
    size_t x_size;

    uint8_t state;

    uint16_t ctrl_packet_num;
    uint8_t senders_gid_array[MAX_IPV6_GID_LENGTH];
    char senders_ip_str[MAX_IP_STRING_LENGTH+1];

    struct uref *output_uref;

    ProbeState probe_state;
    uint16_t pkt_num;
    char ip[INET6_ADDRSTRLEN];

    size_t width;
    size_t height;

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
    struct fi_cq_data_entry comp[1];

    int z = 0;
    do {
        int ret = fi_cq_read (cq, &comp, sizeof(comp) / sizeof(*comp));
        if (ret > 0) {
            if (ret != 1)
                printf("cq_read %d\n", ret);
            (*cur) += ret;
        } else if (ret == -FI_EAGAIN) {
            if (z++ > 10)
                return 1;
            continue;
        } else if (ret == -FI_EAVAIL) {
            struct fi_cq_err_entry cq_err = { 0 };

            int ret = fi_cq_readerr (cq, &cq_err, 0);
            if (ret < 0) {
                fprintf(stderr, "%s(): ret=%d (%s)\n", "fi_cq_readerr", ret, fi_strerror(-ret));
                return ret;
            }

            fprintf(stderr, "X %s\n", fi_cq_strerror (cq, cq_err.prov_errno,
                        cq_err.err_data, NULL, 0));
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

    uint64_t n = upipe_fisrc->rx_cq_cntr % 586;

    struct iovec msg_iov = {
        .iov_base = (uint8_t*)upipe_fisrc->rx_buf + n * UBUF_DEFAULT_SIZE_A,
        .iov_len = UBUF_DEFAULT_SIZE,
    };

    struct fi_msg msg = {
        .msg_iov = &msg_iov,
        .desc = fi_mr_desc (upipe_fisrc->mr),
        .iov_count = 1,
        .addr = 0,
        .context = NULL,
        .data = 0,
    };

    ssize_t s = fi_recvmsg(upipe_fisrc->ep, &msg, FI_RECV);
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
    static const unsigned int packet_buffer_alignment = 8;
    static const unsigned int packet_size = UBUF_DEFAULT_SIZE;
    static const unsigned int packet_count = 586;

    const int aligned_packet_size = (packet_size + packet_buffer_alignment - 1) & ~(packet_buffer_alignment - 1);
    assert(aligned_packet_size == UBUF_DEFAULT_SIZE_A);
    int allocated_size = aligned_packet_size * packet_count;

    upipe_fisrc->x_size = allocated_size;

    size_t buf_size = upipe_fisrc->x_size;

    assert(upipe_fisrc->x_size >= upipe_fisrc->transfer_size);

    errno = 0;
    long alignment = sysconf (_SC_PAGESIZE);
    if (alignment <= 0)
        return 1;

    #define CDI_HUGE_PAGES_BYTE_SIZE    (2 * 1024 * 1024)
    buf_size += CDI_HUGE_PAGES_BYTE_SIZE;
    buf_size &= ~(CDI_HUGE_PAGES_BYTE_SIZE-1);

    upipe_fisrc->buf = mmap(NULL, buf_size, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_HUGETLB, -1, 0);
    if (upipe_fisrc->buf == MAP_FAILED) {
        RET(posix_memalign (&upipe_fisrc->buf, (size_t) alignment, buf_size));
    }

    memset (upipe_fisrc->buf, 0, buf_size);
    upipe_fisrc->rx_buf = upipe_fisrc->buf;

    RET(fi_mr_reg (upipe_fisrc->domain, upipe_fisrc->buf, buf_size,
            FI_RECV, 0, 0, 0, &upipe_fisrc->mr, NULL));

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

    upipe_fisrc->dst_port = FI_DEFAULT_PORT;

    upipe_fisrc->ctrl_packet_num = 0;

    struct fi_info *hints = fi_allocinfo();
    if (!hints) {
    }

    hints->caps = FI_MSG;
    hints->mode = FI_CONTEXT;
    hints->domain_attr->mr_mode =
        FI_MR_LOCAL | FI_MR_ALLOCATED | FI_MR_PROV_KEY | FI_MR_VIRT_ADDR;

    hints->fabric_attr->prov_name = (char*)"sockets";
    hints->ep_attr->type = FI_EP_RDM;
    hints->domain_attr->resource_mgmt = FI_RM_ENABLED;
    hints->domain_attr->threading = FI_THREAD_DOMAIN;
    hints->domain_attr->data_progress = FI_PROGRESS_MANUAL;
    hints->rx_attr->comp_order = FI_ORDER_NONE;

    RET(fi_getinfo (FI_VERSION (FI_MAJOR_VERSION, FI_MINOR_VERSION),
            NULL, NULL, FI_SOURCE /* ? */, hints, &upipe_fisrc->fi));

    RET(fi_fabric (upipe_fisrc->fi->fabric_attr, &upipe_fisrc->fabric, NULL));
    RET(fi_domain (upipe_fisrc->fabric, upipe_fisrc->fi, &upipe_fisrc->domain, NULL));
    struct fi_cq_attr cq_attr = {
        .wait_obj = FI_WAIT_NONE,
        .format = FI_CQ_FORMAT_DATA,
        .size = upipe_fisrc->fi->rx_attr->size,
    };

    RET(fi_cq_open (upipe_fisrc->domain, &cq_attr, &upipe_fisrc->rxcq, &upipe_fisrc->rxcq));

    struct fi_av_attr av_attr = {
        .type = FI_AV_TABLE,
        .count = 1
    };

    RET(fi_av_open (upipe_fisrc->domain, &av_attr, &upipe_fisrc->av, NULL));

    RET(fi_endpoint (upipe_fisrc->domain, upipe_fisrc->fi, &upipe_fisrc->ep, NULL));

    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->av->fid, 0));
    RET(fi_ep_bind(upipe_fisrc->ep, &upipe_fisrc->rxcq->fid, FI_RECV));

    RET(fi_enable (upipe_fisrc->ep));
    RET(alloc_msgs (upipe));

    upipe_fisrc->fd = -1;
    upipe_fisrc->uri = NULL;
    upipe_fisrc->dst.sin_family = AF_INET;

    upipe_fisrc->probe_state = kProbeStateIdle;
    upipe_fisrc->pkt_num = 0;
    upipe_fisrc->ip[0] = '\0';
    upipe_fisrc->width = 0;
    upipe_fisrc->height = 0;

    hints->fabric_attr->prov_name = NULL; // Value is statically allocated, so don't want libfabric to free it.
    fi_freeinfo (hints);

    upipe_throw_ready(upipe);
    return upipe;
}

static void transmit(struct upipe *upipe, ProbeCommand cmd, bool requires_ack, ProbeCommand reply)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

    uint8_t tx_buf[300];
    memset(tx_buf, 0, sizeof(tx_buf));
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
    uint16_t port = upipe_fisrc->dst_port;
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

enum sampling {
    sampling_Unknown,
    sampling_YCbCr422,
    sampling_YCbCr444,
    sampling_RGB,
};

enum colorimetry {
    colorimetry_UNSPECIFIED,
    colorimetry_BT601,
    colorimetry_BT709,
    colorimetry_BT2020,
    colorimetry_BT2100,
    colorimetry_ST2065_1,
    colorimetry_ST2065_3,
    colorimetry_XYZ,
};

enum range {
    range_narrow,
    range_fullprotect,
    range_full,
};

static enum range parse_range(const char *val)
{
    if (!strcmp(val, "FULL"))
        return range_full;
    if (!strcmp(val, "FULLPROTECT"))
        return range_fullprotect;
    if (!strcmp(val, "NARROW"))
        return range_narrow;
    return range_narrow;
}

static enum sampling parse_sampling(const char *val)
{
    if (!strcmp(val, "YCbCr-4:2:2"))
        return sampling_YCbCr422;
    if (!strcmp(val, "YCbCr-4:4:4"))
        return sampling_YCbCr444;
    if (!strcmp(val, "RGB"))
        return sampling_RGB;
    if (!strcmp(val, "YCbCr422")) // LOL
        return sampling_YCbCr422;
    if (!strcmp(val, "YCbCr444"))
        return sampling_YCbCr444;
    return sampling_Unknown;
}

static enum colorimetry parse_colorimetry(const char *val)
{
    if (!strcmp(val, "BT601"))
        return colorimetry_BT601;
    if (!strcmp(val, "BT709"))
        return colorimetry_BT709;
    if (!strcmp(val, "BT2020"))
        return colorimetry_BT2020;
    if (!strcmp(val, "BT2100"))
        return colorimetry_BT2100;
    if (!strcmp(val, "ST2065-1"))
        return colorimetry_ST2065_1;
    if (!strcmp(val, "ST2065-3"))
        return colorimetry_ST2065_3;
    if (!strcmp(val, "XYZ"))
        return colorimetry_XYZ;
    return colorimetry_UNSPECIFIED;
}

static int parse_udict_str(struct ustring u, struct udict *udict)
{
    while (!ustring_is_empty((u = ustring_shift_while(u, " ")))) { /* skip spaces */
        struct ustring sub = ustring_split_sep(&u, ";");     /* split token */

        struct ustring key = ustring_split_sep(&sub, "=");   /* split k = v */
        if (ustring_is_empty(key))
            continue;
        char *k = NULL;
        UBASE_RETURN(ustring_to_str(key, &k));               /* strdup */

        int ret = UBASE_ERR_NONE;
        if (!ustring_is_null(sub)) {                         /* set k = v */
            uint8_t *attr;
            ret = udict_set(udict, k, UDICT_TYPE_STRING, sub.len + 1, &attr);
            if (ret == UBASE_ERR_NONE) {
                memcpy(attr, sub.at, sub.len);
                attr[sub.len] = '\0';
            }
        } else {                                             /* set k */
            ret = udict_set_void(udict, NULL, UDICT_TYPE_VOID, k);
        }

        free(k);
        UBASE_RETURN(ret);
    }

    return UBASE_ERR_NONE;
}

static void parse_cdi_extra(struct upipe *upipe, struct udict_mgr *udict_mgr, uint8_t *extra, size_t n)
{
    struct upipe_fisrc *upipe_fisrc = upipe_fisrc_from_upipe(upipe);

    typedef struct __attribute__((__packed__)) {
        uint16_t stream_identifier;
        char uri[257];
        uint8_t data[1024];
        uint8_t packing[3]; // LOL
        int32_t data_size;
    } CdiAvmConfig;

    if (n < sizeof(CdiAvmConfig)) {
        upipe_err_va(upipe, "Extra data too small (%zu < %zu)",
            n, sizeof(CdiAvmConfig));
        return;
    }
    if (n > sizeof(CdiAvmConfig)) {
        upipe_warn_va(upipe, "Extra data too big (%zu > %zu)",
            n, sizeof(CdiAvmConfig));
    }

    CdiAvmConfig c;
    memcpy(&c, extra, sizeof(c));
    c.uri[sizeof(c.uri) - 1] = '\0';
    c.packing[0] = '\0';

    if (strcmp(c.uri, "https://cdi.elemental.com/specs/baseline-video")) {
        upipe_warn_va(upipe, "Unknown specification %s", c.uri);
        return;
    }

    if (c.data_size > sizeof(c.data)) {
        upipe_warn_va(upipe, "Data size too big (%u > %zu)",
            c.data_size, sizeof(c.data));
        c.data_size = sizeof(c.data);
    }

    struct ustring u;
    u.at = (char*)c.data;
    u.len = c.data_size;
    struct udict *udict = udict_alloc(udict_mgr, 0);
    if (!ubase_check(parse_udict_str(u, udict))) {
        upipe_warn_va(upipe, "parsing extra data failed");
    }

    const char *val;

    uint8_t major = 0, minor = 0;
    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "cdi_profile_version"))) {
        if (sscanf(val, "%2hhu.%2hhu", &major, &minor) != 2) {
            goto end;
        }
    }

    if (major != 1 || minor != 0) {
        upipe_warn_va(upipe, "Unknown cdi_profile_version %d.%d", major, minor);
        goto end;
    }

    enum sampling sampling = sampling_Unknown;
    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "sampling"))) {
        sampling = parse_sampling(val);
    }

    enum colorimetry colorimetry = colorimetry_UNSPECIFIED;
    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "colorimetry"))) {
        colorimetry = parse_colorimetry(val);
    }

    enum range range = range_narrow;
    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "range"))) {
        range = parse_range(val);
    }

    size_t width = 0, height = 0, depth = 0;

    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "width"))) {
        width = atoi(val);
    }

    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "height"))) {
        height = atoi(val);
    }

    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "depth"))) {
        depth = atoi(val);
    }

    struct urational fps;
    if (ubase_check(udict_get_string(udict, &val, UDICT_TYPE_STRING, "exactframerate"))) {
        if (sscanf(val, "%" SCNu64 "/%" SCNu64, &fps.num, &fps.den) != 2) {
            fps.den = 1;
            if (sscanf(val, "%" SCNu64, &fps.num) != 1)
                fps.num = 0;
        }
    }

    if (depth != 10) {
        upipe_err_va(upipe, "Bit depth %zu not supported", depth);
        goto end;
    }

    struct uref *flow_format = NULL;
    switch (sampling) {
    case sampling_YCbCr422:
        if (depth == 8)
            flow_format = uref_pic_flow_alloc_yuv422p(upipe_fisrc->uref_mgr);
        else if (depth == 10)
            flow_format = uref_pic_flow_alloc_yuv422p10le(upipe_fisrc->uref_mgr);
        else if (depth == 12)
            flow_format = uref_pic_flow_alloc_yuv422p12le(upipe_fisrc->uref_mgr);
        else
            break;
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            goto end;
        }
        break;
    case sampling_Unknown: upipe_err(upipe, "Unknown sampling"); break;
    case sampling_YCbCr444: upipe_err(upipe, "Unsupported 444 sampling"); break;
    case sampling_RGB: upipe_err(upipe, "Unsupported RGB sampling"); break;
    }

    switch (colorimetry) {
        default: break; // TODO
    }

    switch (range) {
        default: break; // TODO
    }

    uref_pic_flow_set_hsize(flow_format, width);
    uref_pic_flow_set_vsize(flow_format, height);
    uref_pic_flow_set_fps(flow_format, fps);

    upipe_fisrc_store_flow_def(upipe, flow_format);

    upipe_fisrc->width = width;
    upipe_fisrc->height = height;

    upipe_dbg_va(upipe, "stream id %hu", c.stream_identifier);

end:
    udict_free(udict);
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
    if (!upipe_fisrc->ubuf_mgr)
        upipe_fisrc_check(upipe, NULL);

    for (;;) {
    if (unlikely(upipe_fisrc->uclock != NULL))
        systime = uclock_now(upipe_fisrc->uclock);
    struct uref *uref = upipe_fisrc->output_uref;

    uint64_t n = upipe_fisrc->rx_cq_cntr % 586;
    uint8_t *buffer = upipe_fisrc->rx_buf + n * UBUF_DEFAULT_SIZE_A;
    ssize_t s = rx(upipe);

    size_t offset = 0;
    if (s <= 0)
        return;

    assert(s >= 9);
    assert(s == UBUF_DEFAULT_SIZE);

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
            // TODO : pts

            uint64_t payload_user_data = get_64le(buffer); buffer += 8;

            uint16_t  extra_data_size = get_16le(buffer); buffer += 2;

            uint64_t tx_start_time_microseconds = get_64le(buffer); buffer += 8;
            // TODO : mesure network latency?

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

            parse_cdi_extra(upipe, upipe_fisrc->uref_mgr->udict_mgr, buffer, extra_data_size);
            if (extra_data_size > s)
                extra_data_size = s;
            s -= extra_data_size;
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

    {
//    upipe_dbg_va(upipe, "%s(offset=%zu) at %.6f", __func__, offset, ((float)systime) / 27000000.);
        static uint64_t start;
        if (offset == 0)
            start = systime;
        if (offset + s > 5184000) {
            upipe_dbg_va(upipe, "got pic after %.6f ms", ((float)(systime - start)) / 27000.);
        }
    }

    if (!upipe_fisrc->ubuf_mgr) {
        upipe_err_va(upipe, "NO UBUF");
        return;
    }

    static bool go = false;
    if (offset == 0)
        go = true;
    if (!go)
        return;

    if (unlikely(uref == NULL)) {
        uref = uref_pic_alloc(upipe_fisrc->uref_mgr, upipe_fisrc->ubuf_mgr,
                upipe_fisrc->width, upipe_fisrc->height);
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

    static uint8_t x[5184000];
    if (offset + s > 5184000)
        s = 5184000 - offset;
    memcpy(&x[offset], buffer, s);

    if (offset + s == 5184000) {
        const uint8_t *src = x;
        for (int i = 0; i < 1920*1080; i += 2) {
            uint8_t a = *src++;
            uint8_t b = *src++;
            uint8_t c = *src++;
            uint8_t d = *src++;
            uint8_t e = *src++;
            u[i/2] = (a << 2)          | ((b >> 6) & 0x03); //1111111122
            y[i+0] = ((b & 0x3f) << 4) | ((c >> 4) & 0x0f); //2222223333
            v[i/2] = ((c & 0x0f) << 6) | ((d >> 2) & 0x3f); //3333444444
            y[i+1] = ((d & 0x03) << 8) | e;                 //4455555555
         }
    }

    uref_pic_plane_unmap(uref, "y10l", 0, 0, -1, -1);
    uref_pic_plane_unmap(uref, "u10l", 0, 0, -1, -1);
    uref_pic_plane_unmap(uref, "v10l", 0, 0, -1, -1);

    if (offset + s >= 5184000) {
        upipe_fisrc->output_uref = NULL;
        upipe_fisrc_output(upipe, uref, &upipe_fisrc->upump);
    }
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
        if (upipe_fisrc->flow_def) {
            upipe_fisrc_require_ubuf_mgr(upipe, uref_dup(upipe_fisrc->flow_def));
            return UBASE_ERR_NONE;
        }
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

    upipe_fisrc->dst_port = FI_DEFAULT_PORT;
    char *colon = strrchr(uri, ':');
    if (colon) {
        upipe_fisrc->dst_port = atoi(colon+1);
    }

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

    if (upipe_fisrc->upump != NULL)
        upump_stop(upipe_fisrc->upump);

    fi_close(&upipe_fisrc->mr->fid);
    fi_close(&upipe_fisrc->ep->fid);
    fi_close(&upipe_fisrc->rxcq->fid);
    fi_close(&upipe_fisrc->av->fid);
    fi_close(&upipe_fisrc->domain->fid);
    fi_close(&upipe_fisrc->fabric->fid);

    free (upipe_fisrc->buf); // FIXME : munmap

    fi_freeinfo (upipe_fisrc->fi);

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
