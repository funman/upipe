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
#include "upipe/uref.h"
#include "upipe/uref_block.h"
#include "upipe/uref_block_flow.h"
#include "upipe/upipe.h"
#include "upipe/upipe_helper_upipe.h"
#include "upipe/upipe_helper_subpipe.h"
#include "upipe/upipe_helper_urefcount.h"
#include "upipe/upipe_helper_urefcount_real.h"
#include "upipe/upipe_helper_void.h"
#include "upipe/upipe_helper_uref_mgr.h"
#include "upipe/upipe_helper_ubuf_mgr.h"
#include "upipe/upipe_helper_output.h"
#include "upipe-modules/upipe_srt_handshake.h"

#include <bitstream/haivision/srt.h>

#include <arpa/inet.h>

/** @hidden */
static int upipe_srths_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a SRT handshake pipe. */
struct upipe_srths {
    /** real refcount management structure */
    struct urefcount urefcount_real;
    /** refcount management structure exported to the public structure */
    struct urefcount urefcount;

    struct upipe_mgr sub_mgr;
    /** list of output subpipes */
    struct uchain outputs;

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

    struct upipe *srths_output;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_srths, upipe, UPIPE_SRT_HANDSHAKE_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_srths, urefcount, upipe_srths_no_input)
UPIPE_HELPER_UREFCOUNT_REAL(upipe_srths, urefcount_real, upipe_srths_free);

UPIPE_HELPER_VOID(upipe_srths)

UPIPE_HELPER_OUTPUT(upipe_srths, output, flow_def, output_state, request_list)
UPIPE_HELPER_UREF_MGR(upipe_srths, uref_mgr, uref_mgr_request,
                      upipe_srths_check,
                      upipe_srths_register_output_request,
                      upipe_srths_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srths, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srths_check,
                      upipe_srths_register_output_request,
                      upipe_srths_unregister_output_request)

/** @internal @This is the private context of a SRT handshake output pipe. */
struct upipe_srths_output {
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

static int upipe_srths_output_check(struct upipe *upipe, struct uref *flow_format);
UPIPE_HELPER_UPIPE(upipe_srths_output, upipe, UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
UPIPE_HELPER_VOID(upipe_srths_output);
UPIPE_HELPER_UREFCOUNT(upipe_srths_output, urefcount, upipe_srths_output_free)
UPIPE_HELPER_OUTPUT(upipe_srths_output, output, flow_def, output_state, request_list)
UPIPE_HELPER_UREF_MGR(upipe_srths_output, uref_mgr, uref_mgr_request,
                      upipe_srths_output_check,
                      upipe_srths_output_register_output_request,
                      upipe_srths_output_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srths_output, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srths_output_check,
                      upipe_srths_output_register_output_request,
                      upipe_srths_output_unregister_output_request)
UPIPE_HELPER_SUBPIPE(upipe_srths, upipe_srths_output, output, sub_mgr, outputs,
                     uchain)

static int upipe_srths_output_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srths_output *upipe_srths_output = upipe_srths_output_from_upipe(upipe);
    if (flow_format)
        upipe_srths_output_store_flow_def(upipe, flow_format);

    if (upipe_srths_output->uref_mgr == NULL) {
        upipe_srths_output_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srths_output->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srths_output->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srths_output_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    return UBASE_ERR_NONE;
}

/** @This is called when there is no external reference to the pipe anymore.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srths_no_input(struct upipe *upipe)
{
    upipe_srths_throw_sub_outputs(upipe, UPROBE_SOURCE_END);
    upipe_srths_release_urefcount_real(upipe);
}
/** @internal @This allocates an output subpipe of a dup pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srths_output_alloc(struct upipe_mgr *mgr,
                                            struct uprobe *uprobe,
                                            uint32_t signature, va_list args)
{
    if (mgr->signature != UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
        return NULL;

    struct upipe_srths *upipe_srths = upipe_srths_from_sub_mgr(mgr);
    if (upipe_srths->srths_output)
        return NULL;

    struct upipe *upipe = upipe_srths_output_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

//    struct upipe_srths_output *upipe_srths_output = upipe_srths_output_from_upipe(upipe);

    upipe_srths->srths_output = upipe;

    upipe_srths_output_init_urefcount(upipe);
    upipe_srths_output_init_output(upipe);
    upipe_srths_output_init_sub(upipe);
    upipe_srths_output_init_ubuf_mgr(upipe);
    upipe_srths_output_init_uref_mgr(upipe);

    upipe_throw_ready(upipe);

    upipe_srths_output_require_uref_mgr(upipe);

    return upipe;
}


/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srths_output_free(struct upipe *upipe)
{
    //struct upipe_srths_output *upipe_srths_output = upipe_srths_output_from_upipe(upipe);
    upipe_throw_dead(upipe);

    struct upipe_srths *upipe_srths = upipe_srths_from_sub_mgr(upipe->mgr);
    upipe_srths->srths_output = NULL;
    upipe_srths_output_clean_output(upipe);
    upipe_srths_output_clean_sub(upipe);
    upipe_srths_output_clean_urefcount(upipe);
    upipe_srths_output_clean_ubuf_mgr(upipe);
    upipe_srths_output_clean_uref_mgr(upipe);
    upipe_srths_output_free_void(upipe);
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srths_output_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, "block."))

    if (upipe_srths->srths_output) {
        struct uref *flow_def_dup = uref_dup(flow_def);
        if (unlikely(flow_def_dup == NULL))
            return UBASE_ERR_ALLOC;
        upipe_srths_output_store_flow_def(upipe_srths->srths_output, flow_def_dup);
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
static int _upipe_srths_output_control(struct upipe *upipe,
                                    int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_srths_output_control_super(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srths_output_control_output(upipe, command, args));
    switch (command) {
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_srths_output_set_flow_def(upipe, flow_def);
        }
        default:
            return UBASE_ERR_UNHANDLED;
    }
}
static int upipe_srths_output_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srths_output_control(upipe, command, args))
    return upipe_srths_output_check(upipe, NULL);
}

/** @internal @This handles RTCP data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_srths_output_input(struct upipe *upipe, struct uref *uref,
                                    struct upump **upump_p)
{
    struct upipe_srths_output *upipe_srths_output = upipe_srths_output_from_upipe(upipe);
    struct upipe_srths *upipe_srths = upipe_srths_from_sub_mgr(upipe->mgr);

    if (upipe_srths_output->uref_mgr == NULL || upipe_srths_output->ubuf_mgr == NULL) {
        upipe_srths_output_check(upipe, NULL);
        uref_free(uref);
        return;
    }

    upipe_srths_output_output(upipe, uref, upump_p);
}

/** @internal @This initializes the output manager for a srths set pipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srths_init_sub_mgr(struct upipe *upipe)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);
    struct upipe_mgr *sub_mgr = &upipe_srths->sub_mgr;
    sub_mgr->refcount = upipe_srths_to_urefcount_real(upipe_srths);
    sub_mgr->signature = UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE;
    sub_mgr->upipe_alloc = upipe_srths_output_alloc;
    sub_mgr->upipe_input = upipe_srths_output_input;
    sub_mgr->upipe_control = upipe_srths_output_control;
}


/** @internal @This allocates a SRT handshake pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srths_alloc(struct upipe_mgr *mgr,
                                        struct uprobe *uprobe,
                                        uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_srths_alloc_void(mgr, uprobe, signature, args);
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);

    upipe_srths_init_urefcount(upipe);
    upipe_srths_init_urefcount_real(upipe);
    upipe_srths_init_sub_outputs(upipe);
    upipe_srths_init_sub_mgr(upipe);

    upipe_srths_init_uref_mgr(upipe);
    upipe_srths_init_ubuf_mgr(upipe);
    upipe_srths_init_output(upipe);

    // FIXME
    upipe_srths->socket_id = 0;
    upipe_srths->syn_cookie = 1;
    upipe_srths->expect_conclusion = false;
    upipe_srths->srths_output = NULL;

    upipe_throw_ready(upipe);
    return upipe;
}


/** @internal @This checks if the pump may be allocated.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_srths_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);
    if (flow_format != NULL)
        upipe_srths_store_flow_def(upipe, flow_format);

    if (upipe_srths->uref_mgr == NULL) {
        upipe_srths_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srths->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srths->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srths_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    return UBASE_ERR_NONE;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srths_set_flow_def(struct upipe *upipe, struct uref *flow_def)
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

    upipe_srths_store_flow_def(upipe, flow_def);

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on a SRT handshake pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int _upipe_srths_control(struct upipe *upipe,
                                 int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_srths_control_output(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srths_control_outputs(upipe, command, args));

    switch (command) {
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow = va_arg(args, struct uref *);
            return upipe_srths_set_flow_def(upipe, flow);
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
static int upipe_srths_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srths_control(upipe, command, args));

    return upipe_srths_check(upipe, NULL);
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

static void upipe_srths_input(struct upipe *upipe, struct uref *uref,
        struct upump **upump_p)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);

    size_t total_size;
    ubase_assert(uref_block_size(uref, &total_size));

    int offset = 0;
    while (total_size) {
        const uint8_t *buf;
        int size = total_size;

        ubase_assert(uref_block_read(uref, offset, &size, &buf));

        if (size < SRT_HEADER_SIZE) {
            upipe_err_va(upipe, "Packet too small (%d)", size);
            goto skip;
        }

        if (srt_get_packet_control(buf)) {
            uint16_t type = srt_get_control_packet_type(buf);
            printf("control %s\n", get_ctrl_type(type));
            if (type == SRT_CONTROL_TYPE_HANDSHAKE) {
                const uint8_t *cif = srt_get_control_packet_cif(buf);
                if (!srt_check_handshake(cif, size - SRT_HEADER_SIZE)) {
                    upipe_err(upipe, "Malformed handshake");
                    goto skip;
                }
                uint32_t version = srt_get_handshake_version(cif);
                uint16_t encryption = srt_get_handshake_encryption(cif);
                uint16_t extension = srt_get_handshake_extension(cif);
                uint32_t hs_type = srt_get_handshake_type(cif);
                uint32_t syn_cookie = srt_get_handshake_syn_cookie(cif);
                uint32_t dst_socket_id = srt_get_packet_dst_socket_id(buf);

                if (!upipe_srths->expect_conclusion) {
                    if (version != 4 || encryption != SRT_HANDSHAKE_CIPHER_NONE
                            || extension != SRT_HANDSHAKE_EXT_KMREQ 
                            || hs_type != SRT_HANDSHAKE_TYPE_INDUCTION ||
                            syn_cookie != 0 || dst_socket_id != 0) {
                        upipe_err(upipe, "Malformed handshake");
                        goto skip;
                    }

                    uint32_t socket_id = srt_get_handshake_socket_id(cif);
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
                    struct uref *uref = uref_block_alloc(upipe_srths->uref_mgr,
                            upipe_srths->ubuf_mgr, SRT_HEADER_SIZE + SRT_HANDSHAKE_CIF_SIZE);
                    if (!uref)
                        goto skip;
                    uint8_t *out;
                    int output_size = -1;
                    if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
                        uref_free(uref);
                        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
                    }

                    srt_set_packet_control(out, true);
                    srt_set_packet_timestamp(out, 0); // TODO
                    srt_set_packet_dst_socket_id(out, 0);
                    srt_set_control_packet_type(out, SRT_CONTROL_TYPE_HANDSHAKE);
                    srt_set_control_packet_subtype(out, 0);
                    srt_set_control_packet_type_specific(out, 0);
                    uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);

                    srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION);
                    srt_set_handshake_encryption(out_cif, SRT_HANDSHAKE_CIPHER_NONE);
                    srt_set_handshake_extension(out_cif, SRT_MAGIC_CODE);
                    srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_INDUCTION);
                    srt_set_handshake_syn_cookie(out_cif, upipe_srths->syn_cookie);
                    srt_set_handshake_socket_id(out_cif, upipe_srths->socket_id);

                    upipe_srths->expect_conclusion = true;

                    uref_block_unmap(uref, 0);
                    upipe_srths_output(upipe, uref, upump_p);
                } else {
                    if (version != 5 || encryption != SRT_HANDSHAKE_CIPHER_NONE
                            || hs_type != SRT_HANDSHAKE_TYPE_CONCLUSION
                            || syn_cookie != upipe_srths->syn_cookie
                            || dst_socket_id != upipe_srths->socket_id) {
                        upipe_err(upipe, "Malformed conclusion handshake");
                        upipe_srths->expect_conclusion = false;
                        goto skip;
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

                    struct uref *uref = uref_block_alloc(upipe_srths->uref_mgr,
                            upipe_srths->ubuf_mgr, size);
                    if (!uref)
                        goto skip;
                    uint8_t *out;
                    int output_size = -1;
                    if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
                        uref_free(uref);
                        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
                    }

                    srt_set_packet_control(out, true);
                    srt_set_packet_timestamp(out, 0);
                    srt_set_packet_dst_socket_id(out, 0);
                    srt_set_control_packet_type(out, SRT_CONTROL_TYPE_HANDSHAKE);
                    srt_set_control_packet_subtype(out, 0);
                    srt_set_control_packet_type_specific(out, 0);
                    uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);

                    srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION);
                    srt_set_handshake_encryption(out_cif, SRT_HANDSHAKE_CIPHER_NONE);
                    srt_set_handshake_extension(out_cif, extension);
                    srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_CONCLUSION);
                    srt_set_handshake_syn_cookie(out_cif, 0);
                    srt_set_handshake_socket_id(out_cif, upipe_srths->socket_id);
                    srt_set_handshake_isn(out_cif, srt_get_handshake_isn(cif));
                    srt_set_handshake_mtu(out_cif, srt_get_handshake_mtu(cif));
                    srt_set_handshake_mfw(out_cif, srt_get_handshake_mfw(cif));

                    // TODO: peer
                    srt_set_handshake_extension_type(out_cif, srt_get_handshake_extension_type(cif));
                    uint16_t ext_len = srt_get_handshake_extension_len(cif);
                    srt_set_handshake_extension_len(out_cif, ext_len);

                    // TODO : interpret ext
                    memcpy(((uint8_t*)srt_get_handshake_extension_buf(out_cif)),
                            srt_get_handshake_extension_buf(cif),
                            4 * ext_len);

                    upipe_srths->expect_conclusion = false;

                    uref_block_unmap(uref, 0);
                    upipe_srths_output(upipe, uref, upump_p);
                }
            } else if (type == SRT_CONTROL_TYPE_KEEPALIVE) {
            } else if (type == SRT_CONTROL_TYPE_ACK) {
            } else if (type == SRT_CONTROL_TYPE_NAK) {
            }
        } else {
            assert(upipe_srths->srths_output);
            struct uref *data = uref_dup(uref);

            uint32_t seq = srt_get_data_packet_seq(buf);
            uint32_t position = srt_get_data_packet_position(buf);
            bool order = srt_get_data_packet_order(buf);
            uint8_t encryption = srt_get_data_packet_encryption(buf);
            bool retransmit = srt_get_data_packet_retransmit(buf);
            uint32_t num = srt_get_data_packet_message_number(buf);
            uint32_t ts = srt_get_packet_timestamp(buf);
            uint32_t socket_id = srt_get_packet_dst_socket_id(buf);

            uref_block_resize(data, SRT_HEADER_SIZE, -1);

            upipe_input(upipe_srths->srths_output, data, upump_p);
        }

skip:
        ubase_assert(uref_block_unmap(uref, offset));
        offset += size;
        total_size -= size;
    }

    uref_free(uref);
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srths_free(struct upipe *upipe)
{
    upipe_throw_dead(upipe);

    upipe_srths_clean_output(upipe);
    upipe_srths_clean_ubuf_mgr(upipe);
    upipe_srths_clean_uref_mgr(upipe);
    upipe_srths_clean_urefcount(upipe);
    upipe_srths_clean_urefcount_real(upipe);
    upipe_srths_clean_sub_outputs(upipe);
    upipe_srths_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_srths_mgr = {
    .refcount = NULL,
    .signature = UPIPE_SRT_HANDSHAKE_SIGNATURE,

    .upipe_alloc = upipe_srths_alloc,
    .upipe_input = upipe_srths_input,
    .upipe_control = upipe_srths_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all SRT handshake sources
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_srths_mgr_alloc(void)
{
    return &upipe_srths_mgr;
}
