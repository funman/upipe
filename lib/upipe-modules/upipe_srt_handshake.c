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
#include "upipe/uref_pic.h" // XXX
#include "upipe/uref_clock.h"
#include "upipe/uref_attr.h"
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

#include <gcrypt.h>

/** @hidden */
static int upipe_srt_handshake_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a SRT handshake pipe. */
struct upipe_srt_handshake {
    /** real refcount management structure */
    struct urefcount urefcount_real;
    /** refcount management structure exported to the public structure */
    struct urefcount urefcount;

    struct upipe_mgr sub_mgr;
    /** list of output subpipes */
    struct uchain outputs;

    struct upump_mgr *upump_mgr;
    struct upump *upump_timer;
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
    uint32_t socket_id; /* ours */
    uint32_t remote_socket_id; /* theirs */
    uint32_t isn;
    uint32_t mtu;
    uint32_t mfw;


    uint16_t receiver_tsbpd_delay;
    uint16_t sender_tsbpd_delay;
    uint32_t flags;
    uint16_t major;
    uint8_t minor, patch;

    uint8_t salt[16];
    uint8_t sek[2][32];
    uint8_t sek_len;

    struct sockaddr_storage addr;
    uint64_t establish_time;

    bool expect_conclusion;

    bool listener;
    uint64_t last_hs_sent;

    struct upipe *control;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_srt_handshake, upipe, UPIPE_SRT_HANDSHAKE_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_srt_handshake, urefcount, upipe_srt_handshake_no_input)
UPIPE_HELPER_UREFCOUNT_REAL(upipe_srt_handshake, urefcount_real, upipe_srt_handshake_free);

UPIPE_HELPER_VOID(upipe_srt_handshake)

UPIPE_HELPER_OUTPUT(upipe_srt_handshake, output, flow_def, output_state, request_list)
UPIPE_HELPER_UPUMP_MGR(upipe_srt_handshake, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_srt_handshake, upump_timer, upump_mgr)
UPIPE_HELPER_UCLOCK(upipe_srt_handshake, uclock, uclock_request, NULL, upipe_throw_provide_request, NULL)

UPIPE_HELPER_UREF_MGR(upipe_srt_handshake, uref_mgr, uref_mgr_request,
                      upipe_srt_handshake_check,
                      upipe_srt_handshake_register_output_request,
                      upipe_srt_handshake_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srt_handshake, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srt_handshake_check,
                      upipe_srt_handshake_register_output_request,
                      upipe_srt_handshake_unregister_output_request)

/** @internal @This is the private context of a SRT handshake output pipe. */
struct upipe_srt_handshake_output {
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

static int upipe_srt_handshake_output_check(struct upipe *upipe, struct uref *flow_format);
UPIPE_HELPER_UPIPE(upipe_srt_handshake_output, upipe, UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
UPIPE_HELPER_VOID(upipe_srt_handshake_output);
UPIPE_HELPER_UREFCOUNT(upipe_srt_handshake_output, urefcount, upipe_srt_handshake_output_free)
UPIPE_HELPER_OUTPUT(upipe_srt_handshake_output, output, flow_def, output_state, request_list)
UPIPE_HELPER_UREF_MGR(upipe_srt_handshake_output, uref_mgr, uref_mgr_request,
                      upipe_srt_handshake_output_check,
                      upipe_srt_handshake_output_register_output_request,
                      upipe_srt_handshake_output_unregister_output_request)
UPIPE_HELPER_UBUF_MGR(upipe_srt_handshake_output, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_srt_handshake_output_check,
                      upipe_srt_handshake_output_register_output_request,
                      upipe_srt_handshake_output_unregister_output_request)
UPIPE_HELPER_SUBPIPE(upipe_srt_handshake, upipe_srt_handshake_output, output, sub_mgr, outputs,
                     uchain)

static int upipe_srt_handshake_output_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srt_handshake_output *upipe_srt_handshake_output = upipe_srt_handshake_output_from_upipe(upipe);
    if (flow_format)
        upipe_srt_handshake_output_store_flow_def(upipe, flow_format);

    if (upipe_srt_handshake_output->uref_mgr == NULL) {
        upipe_srt_handshake_output_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt_handshake_output->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srt_handshake_output->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srt_handshake_output_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    return UBASE_ERR_NONE;
}

/** @This is called when there is no external reference to the pipe anymore.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_handshake_no_input(struct upipe *upipe)
{
    upipe_srt_handshake_throw_sub_outputs(upipe, UPROBE_SOURCE_END);
    upipe_srt_handshake_release_urefcount_real(upipe);
}
/** @internal @This allocates an output subpipe of a dup pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srt_handshake_output_alloc(struct upipe_mgr *mgr,
                                            struct uprobe *uprobe,
                                            uint32_t signature, va_list args)
{
    if (mgr->signature != UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE)
        return NULL;

    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_sub_mgr(mgr);
    if (upipe_srt_handshake->control)
        return NULL;

    struct upipe *upipe = upipe_srt_handshake_output_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

//    struct upipe_srt_handshake_output *upipe_srt_handshake_output = upipe_srt_handshake_output_from_upipe(upipe);

    upipe_srt_handshake->control = upipe;

    upipe_srt_handshake_output_init_urefcount(upipe);
    upipe_srt_handshake_output_init_output(upipe);
    upipe_srt_handshake_output_init_sub(upipe);
    upipe_srt_handshake_output_init_ubuf_mgr(upipe);
    upipe_srt_handshake_output_init_uref_mgr(upipe);

    upipe_throw_ready(upipe);

    upipe_srt_handshake_output_require_uref_mgr(upipe);

    return upipe;
}


/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_handshake_output_free(struct upipe *upipe)
{
    upipe_throw_dead(upipe);

    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_sub_mgr(upipe->mgr);
    upipe_srt_handshake->control = NULL;
    upipe_srt_handshake_output_clean_output(upipe);
    upipe_srt_handshake_output_clean_sub(upipe);
    upipe_srt_handshake_output_clean_urefcount(upipe);
    upipe_srt_handshake_output_clean_ubuf_mgr(upipe);
    upipe_srt_handshake_output_clean_uref_mgr(upipe);
    upipe_srt_handshake_output_free_void(upipe);
}

static struct uref *upipe_srt_handshake_alloc_hs(struct upipe *upipe, int ext_size, uint32_t timestamp, uint8_t **cif)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    int size = SRT_HEADER_SIZE + SRT_HANDSHAKE_CIF_SIZE + ext_size;

    struct uref *uref = uref_block_alloc(upipe_srt_handshake->uref_mgr,
            upipe_srt_handshake->ubuf_mgr, size);
    if (!uref) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return NULL;
    }

    uint8_t *out;
    int output_size = -1;
    if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
        uref_free(uref);
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return NULL;
    }

    memset(out, 0, output_size);

    srt_set_packet_control(out, true);
    srt_set_packet_timestamp(out, timestamp);
    srt_set_packet_dst_socket_id(out, upipe_srt_handshake->remote_socket_id);

    srt_set_control_packet_type(out, SRT_CONTROL_TYPE_HANDSHAKE);
    srt_set_control_packet_subtype(out, 0);
    srt_set_control_packet_type_specific(out, 0);


    uint8_t *out_cif = (uint8_t*)srt_get_control_packet_cif(out);
    *cif = out_cif;

    srt_set_handshake_syn_cookie(out_cif, upipe_srt_handshake->syn_cookie);
    srt_set_handshake_mtu(out_cif, upipe_srt_handshake->mtu);
    srt_set_handshake_mfw(out_cif, upipe_srt_handshake->mfw);
    srt_set_handshake_socket_id(out_cif, upipe_srt_handshake->socket_id);
    srt_set_handshake_isn(out_cif, upipe_srt_handshake->isn);

    srt_set_handshake_ip(out_cif, (const struct sockaddr*)&upipe_srt_handshake->addr);

    srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION);
    srt_set_handshake_encryption(out_cif, SRT_HANDSHAKE_CIPHER_NONE);

    return uref;
}

static void upipe_srt_handshake_timer(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    uint64_t now = uclock_now(upipe_srt_handshake->uclock);

    if (now - upipe_srt_handshake->last_hs_sent < UCLOCK_FREQ / 10) {
        return;
    }

    //send HS
    uint8_t *out_cif;
    struct uref *uref = upipe_srt_handshake_alloc_hs(upipe, 0, 0, &out_cif);
    if (!uref)
        return;

    upipe_srt_handshake->establish_time = now;

    srt_set_handshake_version(out_cif, SRT_HANDSHAKE_VERSION_MIN); // XXX
    srt_set_handshake_extension(out_cif, SRT_HANDSHAKE_EXT_KMREQ);
    srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_INDUCTION);

    uref_block_unmap(uref, 0);

    /* control goes through subpipe */
    upipe_srt_handshake_output_output(upipe_srt_handshake->control, uref,
            &upipe_srt_handshake->upump_timer);
    upipe_srt_handshake->last_hs_sent = now;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srt_handshake_output_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, "block."))

    if (upipe_srt_handshake->control) {
        struct uref *flow_def_dup = uref_dup(flow_def);
        if (unlikely(flow_def_dup == NULL))
            return UBASE_ERR_ALLOC;
        upipe_srt_handshake_output_store_flow_def(upipe_srt_handshake->control, flow_def_dup);
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
static int _upipe_srt_handshake_output_control(struct upipe *upipe,
                                    int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_srt_handshake_output_control_super(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srt_handshake_output_control_output(upipe, command, args));
    switch (command) {
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_srt_handshake_output_set_flow_def(upipe, flow_def);
        }
        default:
            return UBASE_ERR_UNHANDLED;
    }
}
static int upipe_srt_handshake_output_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srt_handshake_output_control(upipe, command, args))
    return upipe_srt_handshake_output_check(upipe, NULL);
}

/** @internal @This initializes the output manager for a srt set pipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_handshake_init_sub_mgr(struct upipe *upipe)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    struct upipe_mgr *sub_mgr = &upipe_srt_handshake->sub_mgr;
    sub_mgr->refcount = upipe_srt_handshake_to_urefcount_real(upipe_srt_handshake);
    sub_mgr->signature = UPIPE_SRT_HANDSHAKE_OUTPUT_SIGNATURE;
    sub_mgr->upipe_alloc = upipe_srt_handshake_output_alloc;
    sub_mgr->upipe_input = NULL;
    sub_mgr->upipe_control = upipe_srt_handshake_output_control;
}


/** @internal @This allocates a SRT handshake pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_srt_handshake_alloc(struct upipe_mgr *mgr,
                                        struct uprobe *uprobe,
                                        uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_srt_handshake_alloc_void(mgr, uprobe, signature, args);
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    if (!gcry_control(GCRYCTL_INITIALIZATION_FINISHED_P)) {
        uprobe_err(uprobe, upipe, "Application did not initialize libgcrypt, see "
        "https://www.gnupg.org/documentation/manuals/gcrypt/Initializing-the-library.html");
        upipe_srt_handshake_free_void(upipe);
        return NULL;
    }


    upipe_srt_handshake_init_urefcount(upipe);
    upipe_srt_handshake_init_urefcount_real(upipe);
    upipe_srt_handshake_init_sub_outputs(upipe);
    upipe_srt_handshake_init_sub_mgr(upipe);

    upipe_srt_handshake_init_uref_mgr(upipe);
    upipe_srt_handshake_init_ubuf_mgr(upipe);
    upipe_srt_handshake_init_output(upipe);

    upipe_srt_handshake_init_upump_mgr(upipe);
    upipe_srt_handshake_init_upump_timer(upipe);
    upipe_srt_handshake_init_uclock(upipe);
    upipe_srt_handshake_require_uclock(upipe);

    upipe_srt_handshake->socket_id = 77; // TODO: random?
    upipe_srt_handshake->syn_cookie = 0; // TODO
    upipe_srt_handshake->isn = 0;
    upipe_srt_handshake->remote_socket_id = 0; // will be set with remote first packet
    upipe_srt_handshake->mtu = 1500;
    upipe_srt_handshake->mfw = 8192;
    upipe_srt_handshake->addr.ss_family = 0;

    upipe_srt_handshake->listener = true;
    upipe_srt_handshake->last_hs_sent = 0;
    
    upipe_srt_handshake->expect_conclusion = false;
    upipe_srt_handshake->control = NULL;

    upipe_srt_handshake->receiver_tsbpd_delay = 0;
    upipe_srt_handshake->sender_tsbpd_delay = 0;
    upipe_srt_handshake->flags = 0;
    upipe_srt_handshake->major = 0;
    upipe_srt_handshake->minor = 0;
    upipe_srt_handshake->patch = 0;

    upipe_srt_handshake->sek_len = 0;

    upipe_throw_ready(upipe);
    return upipe;
}


/** @internal @This checks if the pump may be allocated.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_srt_handshake_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    upipe_srt_handshake_check_upump_mgr(upipe);

    if (flow_format != NULL) {
        upipe_srt_handshake_store_flow_def(upipe, flow_format);
    }

    if (upipe_srt_handshake->uref_mgr == NULL) {
        upipe_srt_handshake_require_uref_mgr(upipe);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt_handshake->ubuf_mgr == NULL) {
        struct uref *flow_format =
            uref_block_flow_alloc_def(upipe_srt_handshake->uref_mgr, NULL);
        if (unlikely(flow_format == NULL)) {
            upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
            return UBASE_ERR_ALLOC;
        }
        upipe_srt_handshake_require_ubuf_mgr(upipe, flow_format);
        return UBASE_ERR_NONE;
    }

    if (upipe_srt_handshake->upump_mgr && !upipe_srt_handshake->upump_timer && !upipe_srt_handshake->listener) {
        struct upump *upump =
            upump_alloc_timer(upipe_srt_handshake->upump_mgr,
                              upipe_srt_handshake_timer,
                              upipe, upipe->refcount,
                              UCLOCK_FREQ/300, UCLOCK_FREQ/300);
        upump_start(upump);
        upipe_srt_handshake_set_upump_timer(upipe, upump);
    }

    return UBASE_ERR_NONE;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_srt_handshake_set_flow_def(struct upipe *upipe, struct uref *flow_def)
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

    upipe_srt_handshake_store_flow_def(upipe, flow_def);
    /* force sending flow definition immediately */
    upipe_srt_handshake_output(upipe, NULL, NULL);

    return UBASE_ERR_NONE;
}

static int upipe_srt_handshake_set_option(struct upipe *upipe, const char *option,
        const char *value)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    if (!option || !value)
        return UBASE_ERR_INVALID;

    if (!strcmp(option, "listener")) {
        upipe_srt_handshake->listener = strcmp(value, "0");
        return UBASE_ERR_NONE;
    }

    upipe_err_va(upipe, "Unknown option %s", option);
    return UBASE_ERR_INVALID;
}

/** @internal @This processes control commands on a SRT handshake pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int _upipe_srt_handshake_control(struct upipe *upipe,
                                 int command, va_list args)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    UBASE_HANDLED_RETURN(upipe_srt_handshake_control_output(upipe, command, args));
    UBASE_HANDLED_RETURN(upipe_srt_handshake_control_outputs(upipe, command, args));

    switch (command) {
        case UPIPE_ATTACH_UPUMP_MGR:
            upipe_srt_handshake_set_upump_timer(upipe, NULL);
            return upipe_srt_handshake_attach_upump_mgr(upipe);

        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow = va_arg(args, struct uref *);
            return upipe_srt_handshake_set_flow_def(upipe, flow);
        }

        case UPIPE_SET_OPTION: {
            const char *option = va_arg(args, const char *);
            const char *value  = va_arg(args, const char *);
            return upipe_srt_handshake_set_option(upipe, option, value);
        }

        case UPIPE_SRT_HANDSHAKE_SET_PEER: {
            UBASE_SIGNATURE_CHECK(args, UPIPE_SRT_HANDSHAKE_SIGNATURE)
            const struct sockaddr *s = va_arg(args, const struct sockaddr *);
            socklen_t addrlen = va_arg(args, socklen_t);
            if (addrlen > sizeof(upipe_srt_handshake->addr))
                addrlen = sizeof(upipe_srt_handshake->addr);
            memcpy(&upipe_srt_handshake->addr, s, addrlen);
            return UBASE_ERR_NONE;
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
static int upipe_srt_handshake_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_RETURN(_upipe_srt_handshake_control(upipe, command, args));

    return upipe_srt_handshake_check(upipe, NULL);
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

static void upipe_srt_handshake_finalize(struct upipe *upipe)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    upipe_srt_handshake->expect_conclusion = false;

    struct uref *flow_def;
    if (ubase_check(upipe_srt_handshake_get_flow_def(upipe, &flow_def))) {
        flow_def = uref_dup(flow_def);
        if (flow_def) {
            uref_flow_set_id(flow_def, upipe_srt_handshake->remote_socket_id);
            struct udict_opaque opaque;
            opaque.v = upipe_srt_handshake->salt;
            opaque.size = 16;
            if (!ubase_check(uref_attr_set_opaque(flow_def, opaque, UDICT_TYPE_OPAQUE, "enc.salt")))
                upipe_err(upipe, "damn");

            opaque.v = upipe_srt_handshake->sek[0];
            opaque.size = upipe_srt_handshake->sek_len;
            if (!ubase_check(uref_attr_set_opaque(flow_def, opaque, UDICT_TYPE_OPAQUE, "enc.even_key")))
                upipe_err(upipe, "damn");

            // TODO: odd key

            uref_pic_set_number(flow_def, upipe_srt_handshake->isn);
            upipe_srt_handshake_store_flow_def(upipe, flow_def);
            /* force sending flow definition immediately */
            upipe_srt_handshake_output(upipe, NULL, NULL);
        }
    }
}

static void upipe_srt_handshake_parse_hsreq(struct upipe *upipe, const uint8_t *ext)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    srt_get_handshake_extension_srt_version(ext, &upipe_srt_handshake->major, &upipe_srt_handshake->minor, &upipe_srt_handshake->patch);
    upipe_dbg_va(upipe, "SRT lib version %u.%u.%u", upipe_srt_handshake->major, upipe_srt_handshake->minor, upipe_srt_handshake->patch);

    uint32_t flags = srt_get_handshake_extension_srt_flags(ext);
    upipe_dbg_va(upipe, "%s%s%s%s%s%s%s%s",
        (flags & SRT_HANDSHAKE_EXT_FLAG_TSBPDSND) ? "TSBPDSND " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_TSBPDRCV) ? "TSBPDRCV " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_CRYPT) ? "CRYPT " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_TLPKTDROP) ? "TLPKTDROP " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_PERIODICNAK) ? "PERIODICNAK " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_REXMITFLG) ? "REXMITFLG " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_STREAM) ? "STREAM " : "",
        (flags & SRT_HANDSHAKE_EXT_FLAG_PACKET_FILTER) ? "PACKET_FILTER " : "");
    upipe_srt_handshake->flags = flags;

    upipe_srt_handshake->receiver_tsbpd_delay = srt_get_handshake_extension_receiver_tsbpd_delay(ext);
    upipe_srt_handshake->sender_tsbpd_delay = srt_get_handshake_extension_sender_tsbpd_delay(ext);
    upipe_dbg_va(upipe, "tsbpd delays: receiver %u, sender %u",
            upipe_srt_handshake->receiver_tsbpd_delay, upipe_srt_handshake->sender_tsbpd_delay);
}

static bool upipe_srt_handshake_parse_kmreq(struct upipe *upipe, const uint8_t *ext, uint8_t *kk, const uint8_t **wrap, uint8_t *wrap_len)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    *kk = srt_km_get_kk(ext);
    uint8_t cipher = srt_km_get_cipher(ext);
    if (cipher != SRT_KMREQ_CIPHER_AES) {
        upipe_err_va(upipe, "Unsupported cipher %u", cipher);
        return false;
    }

    uint8_t klen = 4 * srt_km_get_klen(ext);

    memcpy(upipe_srt_handshake->salt, srt_km_get_salt(ext), 16);

    *wrap = srt_km_get_wrap((uint8_t*)ext);

    uint8_t kek[32];
    const char *pass = "hunter2222"; // FIXME

    gpg_error_t err = gcry_kdf_derive (pass, strlen(pass), GCRY_KDF_PBKDF2, GCRY_MD_SHA1,
            &upipe_srt_handshake->salt[8], 8, 2048, klen, kek);
    if (err) {
        printf("pbkdf2 failed (%s)\n", gcry_strerror(err));
        exit(0);
        return false;
    }

    *wrap_len = ((*kk == 3) ? 2 : 1) * klen + 8;

    uint8_t osek[32];

    gcry_cipher_hd_t aes;
    err = gcry_cipher_open(&aes, GCRY_CIPHER_AES, GCRY_CIPHER_MODE_AESWRAP, 0);
    if (err) {
        printf("cipher open failed (0x%x)\n", err);
        return false;
    }

    err = gcry_cipher_setkey(aes, kek, klen);
    assert(!err);

    err = gcry_cipher_decrypt(aes, osek, 16, *wrap, *wrap_len);
    assert(!err);

    gcry_cipher_close(aes);

    upipe_srt_handshake->sek_len = klen;
    memcpy(upipe_srt_handshake->sek[0], osek, klen);

    return true;
}

static struct uref *upipe_srt_handshake_handle_hs(struct upipe *upipe, const uint8_t *buf, int size, uint64_t now)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    uint32_t timestamp = (now - upipe_srt_handshake->establish_time) / 27;

    uint8_t *out_cif;
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

    if (!upipe_srt_handshake->listener) {
        if (upipe_srt_handshake->expect_conclusion) {
            upipe_srt_handshake_set_upump_timer(upipe, NULL);
            // check 
            upipe_srt_handshake->remote_socket_id = srt_get_handshake_socket_id(cif);

            upipe_srt_handshake_finalize(upipe);
            return NULL;
        }

        /* */
        if (version != SRT_HANDSHAKE_VERSION || dst_socket_id != upipe_srt_handshake->socket_id
                || encryption != SRT_HANDSHAKE_CIPHER_NONE
                || hs_type != SRT_HANDSHAKE_TYPE_INDUCTION
           ) {
            upipe_err_va(upipe, "Malformed handshake (%08x != %08x)",
                    dst_socket_id, upipe_srt_handshake->socket_id);
            return NULL;
        }

        upipe_srt_handshake->mtu = srt_get_handshake_mtu(cif);
        upipe_srt_handshake->mfw = srt_get_handshake_mfw(cif);
        upipe_srt_handshake->isn = srt_get_handshake_isn(cif);

        upipe_dbg_va(upipe, "mtu %u mfw %u isn %u", upipe_srt_handshake->mtu, upipe_srt_handshake->mfw, upipe_srt_handshake->isn);
        upipe_verbose_va(upipe, "cookie %08x", syn_cookie);

        upipe_srt_handshake->syn_cookie = syn_cookie;
        const size_t ext_size = SRT_HANDSHAKE_HSREQ_SIZE;
        struct uref *uref = upipe_srt_handshake_alloc_hs(upipe, ext_size + SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE, timestamp, &out_cif);
        if (!uref)
            return NULL;

        uint8_t *out_ext = srt_get_handshake_extension_buf(out_cif);

        srt_set_handshake_extension(out_cif, SRT_HANDSHAKE_EXT_HSREQ);
        srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_CONCLUSION);
        srt_set_handshake_extension_type(out_ext, SRT_HANDSHAKE_EXT_TYPE_HSREQ);
        srt_set_handshake_extension_len(out_ext, ext_size / 4);
        out_ext += SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE;

        srt_set_handshake_extension_srt_version(out_ext, 2, 2, 2); // made up version
        uint32_t flags = SRT_HANDSHAKE_EXT_FLAG_CRYPT | SRT_HANDSHAKE_EXT_FLAG_PERIODICNAK
            | SRT_HANDSHAKE_EXT_FLAG_REXMITFLG | SRT_HANDSHAKE_EXT_FLAG_TSBPDSND | SRT_HANDSHAKE_EXT_FLAG_TSBPDRCV | SRT_HANDSHAKE_EXT_FLAG_TLPKTDROP;
        srt_set_handshake_extension_srt_flags(out_ext, flags);
        srt_set_handshake_extension_receiver_tsbpd_delay(out_ext, 120); // made up delays
        srt_set_handshake_extension_sender_tsbpd_delay(out_ext, 120);

        upipe_srt_handshake->expect_conclusion = true;

        uref_block_unmap(uref, 0);
        return uref;
    }

    if (!upipe_srt_handshake->expect_conclusion) {
        if (version != SRT_HANDSHAKE_VERSION_MIN || encryption != SRT_HANDSHAKE_CIPHER_NONE
                || extension != SRT_HANDSHAKE_EXT_KMREQ 
                || hs_type != SRT_HANDSHAKE_TYPE_INDUCTION ||
                syn_cookie != 0 || dst_socket_id != 0) {
            upipe_err_va(upipe, "Malformed first handshake syn %u dst_id %u", syn_cookie, dst_socket_id);
            return NULL;
        }

        upipe_srt_handshake->establish_time = now;
        timestamp = 0;
        upipe_srt_handshake->remote_socket_id = srt_get_handshake_socket_id(cif);

        struct uref *uref = upipe_srt_handshake_alloc_hs(upipe, 0, timestamp, &out_cif);
        if (!uref)
            return NULL;

        srt_set_handshake_extension(out_cif, SRT_MAGIC_CODE);
        srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_INDUCTION);

        upipe_srt_handshake->expect_conclusion = true;

        uref_block_unmap(uref, 0);
        return uref;
    } else {
        if (version != SRT_HANDSHAKE_VERSION || encryption != SRT_HANDSHAKE_CIPHER_NONE
                || hs_type != SRT_HANDSHAKE_TYPE_CONCLUSION
                || syn_cookie != upipe_srt_handshake->syn_cookie
                || dst_socket_id != 0) {
            upipe_err(upipe, "Malformed conclusion handshake");
            upipe_srt_handshake->expect_conclusion = false;
            return NULL;
        }

        /* At least HSREQ is expected */
        size -= SRT_HEADER_SIZE + SRT_HANDSHAKE_CIF_SIZE;
        if (size < SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE + SRT_HANDSHAKE_HSREQ_SIZE) {
            upipe_err(upipe, "Malformed conclusion handshake");
            upipe_srt_handshake->expect_conclusion = false;
            return NULL;
        }

        upipe_srt_handshake->isn = srt_get_handshake_isn(cif);

        uint8_t *ext = srt_get_handshake_extension_buf((uint8_t*)cif);

        uint8_t kk = 0;
        const uint8_t *wrap;
        uint8_t wrap_len = 0;

        while (size >= SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE) {
            uint16_t ext_type = srt_get_handshake_extension_type(ext);
            uint16_t ext_len = 4 * srt_get_handshake_extension_len(ext);

            size -= SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE;
            ext += SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE;

            if (ext_len > size) {
                upipe_err_va(upipe, "Malformed extension: %u > %u", ext_len, size);
                break;
            }

            if (ext_type == SRT_HANDSHAKE_EXT_TYPE_HSREQ) {
                if (ext_len >= SRT_HANDSHAKE_HSREQ_SIZE) 
                    upipe_srt_handshake_parse_hsreq(upipe, ext);
                else
                    upipe_err_va(upipe, "Malformed HSREQ: %u < %u\n", ext_len,
                            SRT_HANDSHAKE_HSREQ_SIZE);
            } else if (ext_type == SRT_HANDSHAKE_EXT_TYPE_KMREQ) {
                if (!srt_check_km(ext, ext_len) || !upipe_srt_handshake_parse_kmreq(upipe, ext, &kk, &wrap, &wrap_len))
                    upipe_err(upipe, "Malformed KMREQ");
            }

            ext += ext_len;
            size -= ext_len;
        }

        size = SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE + SRT_HANDSHAKE_HSREQ_SIZE;
        if (wrap_len)
            size += SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE + SRT_KMREQ_COMMON_SIZE + wrap_len;

        struct uref *uref = upipe_srt_handshake_alloc_hs(upipe, size, timestamp, &out_cif);
        if (!uref)
            return NULL;

        srt_set_handshake_extension(out_cif, extension);
        srt_set_handshake_type(out_cif, SRT_HANDSHAKE_TYPE_CONCLUSION);

        ext = srt_get_handshake_extension_buf((uint8_t*)cif);
        uint8_t *out_ext = srt_get_handshake_extension_buf(out_cif);

        srt_set_handshake_extension_type(out_ext, SRT_HANDSHAKE_EXT_TYPE_HSRSP);
        srt_set_handshake_extension_len(out_ext, SRT_HANDSHAKE_HSREQ_SIZE / 4);
        out_ext += SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE;
        srt_set_handshake_extension_srt_version(out_ext, upipe_srt_handshake->major,
                upipe_srt_handshake->minor, upipe_srt_handshake->patch);
        srt_set_handshake_extension_srt_flags(out_ext, upipe_srt_handshake->flags);
        srt_set_handshake_extension_sender_tsbpd_delay(out_ext, upipe_srt_handshake->sender_tsbpd_delay);
        srt_set_handshake_extension_receiver_tsbpd_delay(out_ext, upipe_srt_handshake->receiver_tsbpd_delay);

        out_ext += SRT_HANDSHAKE_HSREQ_SIZE;

        if (wrap_len) {
            srt_set_handshake_extension_type(out_ext, SRT_HANDSHAKE_EXT_TYPE_KMRSP);
            srt_set_handshake_extension_len(out_ext, (SRT_KMREQ_COMMON_SIZE + wrap_len) / 4);
            out_ext += SRT_HANDSHAKE_CIF_EXTENSION_MIN_SIZE;
            memset(out_ext, 0, SRT_KMREQ_COMMON_SIZE);
            // XXX: move to bitstream?

            out_ext[0] = 0x12;  // S V PT
            out_ext[1] = 0x20; out_ext[2] = 0x29; // Sign
            srt_km_set_kk(out_ext, kk);
            srt_km_set_cipher(out_ext, SRT_KMREQ_CIPHER_AES);
            out_ext[10] = 2; // SE
            out_ext[14] = 4; // slen;
            srt_km_set_klen(out_ext, upipe_srt_handshake->sek_len / 4);
            memcpy(&out_ext[SRT_KMREQ_COMMON_SIZE-16], upipe_srt_handshake->salt, 16);
            memcpy(&out_ext[SRT_KMREQ_COMMON_SIZE], wrap, wrap_len);
        }

        upipe_srt_handshake_finalize(upipe);

        uref_block_unmap(uref, 0);
        return uref;
    }
}

static struct uref *upipe_srt_handshake_handle_ack(struct upipe *upipe, const uint8_t *buf, int size, uint64_t now)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);
    uint32_t timestamp = (now - upipe_srt_handshake->establish_time) / 27;

    struct uref *uref = uref_block_alloc(upipe_srt_handshake->uref_mgr,
            upipe_srt_handshake->ubuf_mgr, SRT_HEADER_SIZE + 4 /* WTF */);
    if (!uref)
        return NULL;
    uint8_t *out;
    int output_size = -1;
    if (unlikely(!ubase_check(uref_block_write(uref, 0, &output_size, &out)))) {
        uref_free(uref);
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
    }

    srt_set_packet_control(out, true);
    srt_set_packet_timestamp(out, timestamp);
    srt_set_packet_dst_socket_id(out, upipe_srt_handshake->remote_socket_id);
    srt_set_control_packet_type(out, SRT_CONTROL_TYPE_ACKACK);
    srt_set_control_packet_subtype(out, 0);
    srt_set_control_packet_type_specific(out, srt_get_control_packet_type_specific(buf));

    uref_block_unmap(uref, 0);
    return uref;
    // should go to sender
}

static struct uref *upipe_srt_handshake_input_control(struct upipe *upipe, const uint8_t *buf, int size, bool *handled)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

    uint16_t type = srt_get_control_packet_type(buf);
    uint64_t now = uclock_now(upipe_srt_handshake->uclock);

    upipe_verbose_va(upipe, "control pkt %s", get_ctrl_type(type));
    *handled = true;

    if (type == SRT_CONTROL_TYPE_HANDSHAKE) {
        return upipe_srt_handshake_handle_hs(upipe, buf, size, now);
    } else if (type == SRT_CONTROL_TYPE_KEEPALIVE) {
    } else if (type == SRT_CONTROL_TYPE_ACK) {
        return upipe_srt_handshake_handle_ack(upipe, buf, size, now);
    } else if (type == SRT_CONTROL_TYPE_NAK) {
    } else if (type == SRT_CONTROL_TYPE_ACKACK) {
    } else if (type == SRT_CONTROL_TYPE_SHUTDOWN) {
        exit(0);
    } else {
        *handled = false;
    }

    return NULL;
}

static void upipe_srt_handshake_input(struct upipe *upipe, struct uref *uref,
        struct upump **upump_p)
{
    struct upipe_srt_handshake *upipe_srt_handshake = upipe_srt_handshake_from_upipe(upipe);

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
        bool handled = false;
        struct uref *reply = upipe_srt_handshake_input_control(upipe, buf, size, &handled);
        ubase_assert(uref_block_unmap(uref, 0));
        if (!handled && !reply) {
            upipe_srt_handshake_output(upipe, uref, upump_p);
        } else {
            uref_free(uref);
            if (reply) {
                upipe_srt_handshake_output_output(upipe_srt_handshake->control, reply, upump_p);
            }
        }
    } else {
        ubase_assert(uref_block_unmap(uref, 0));
        /* let data packets pass through */
        upipe_srt_handshake_output(upipe, uref, upump_p);
    }
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srt_handshake_free(struct upipe *upipe)
{
    upipe_throw_dead(upipe);

    upipe_srt_handshake_clean_output(upipe);
    upipe_srt_handshake_clean_upump_timer(upipe);
    upipe_srt_handshake_clean_upump_mgr(upipe);
    upipe_srt_handshake_clean_uclock(upipe);
    upipe_srt_handshake_clean_ubuf_mgr(upipe);
    upipe_srt_handshake_clean_uref_mgr(upipe);
    upipe_srt_handshake_clean_urefcount(upipe);
    upipe_srt_handshake_clean_urefcount_real(upipe);
    upipe_srt_handshake_clean_sub_outputs(upipe);
    upipe_srt_handshake_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_srt_handshake_mgr = {
    .refcount = NULL,
    .signature = UPIPE_SRT_HANDSHAKE_SIGNATURE,

    .upipe_alloc = upipe_srt_handshake_alloc,
    .upipe_input = upipe_srt_handshake_input,
    .upipe_control = upipe_srt_handshake_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all SRT handshake sources
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_srt_handshake_mgr_alloc(void)
{
    return &upipe_srt_handshake_mgr;
}
