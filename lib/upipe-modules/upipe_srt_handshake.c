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
#include "upipe/upipe_helper_urefcount.h"
#include "upipe/upipe_helper_void.h"
#include "upipe/upipe_helper_uref_mgr.h"
#include "upipe/upipe_helper_ubuf_mgr.h"
#include "upipe/upipe_helper_output.h"
#include "upipe-modules/upipe_srt_handshake.h"

/** @hidden */
static int upipe_srths_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a SRT handshake pipe. */
struct upipe_srths {
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

    /** pipe acting as output */
    struct upipe *output;
    /** flow definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    /** SRT handshake uri */
    char *uri;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_srths, upipe, UPIPE_SRT_HANDSHAKE_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_srths, urefcount, upipe_srths_free)
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
    upipe_srths_init_uref_mgr(upipe);
    upipe_srths_init_ubuf_mgr(upipe);
    upipe_srths_init_output(upipe);
    upipe_srths->uri = NULL;
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

/** @internal @This returns the uri of the currently opened SRT handshake.
 *
 * @param upipe description structure of the pipe
 * @param uri_p filled in with the uri of the SRT handshake
 * @return an error code
 */
static int upipe_srths_get_uri(struct upipe *upipe, const char **uri_p)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);
    assert(uri_p != NULL);
    *uri_p = upipe_srths->uri;
    return UBASE_ERR_NONE;
}

/** @internal @This asks to open the given SRT handshake.
 *
 * @param upipe description structure of the pipe
 * @param uri relative or absolute uri of the SRT handshake
 * @return an error code
 */
static int upipe_srths_set_uri(struct upipe *upipe, const char *uri)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);

    ubase_clean_str(&upipe_srths->uri);

    if (unlikely(uri == NULL))
        return UBASE_ERR_NONE;

    upipe_srths->uri = strdup(uri);
    if (unlikely(upipe_srths->uri == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return UBASE_ERR_ALLOC;
    }
    upipe_notice_va(upipe, "opening SRT handshake %s", upipe_srths->uri);
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
    switch (command) {
        case UPIPE_GET_FLOW_DEF:
        case UPIPE_GET_OUTPUT:
        case UPIPE_SET_OUTPUT:
            return upipe_srths_control_output(upipe, command, args);

        case UPIPE_GET_URI: {
            const char **uri_p = va_arg(args, const char **);
            return upipe_srths_get_uri(upipe, uri_p);
        }
        case UPIPE_SET_URI: {
            const char *uri = va_arg(args, const char *);
            return upipe_srths_set_uri(upipe, uri);
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

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_srths_free(struct upipe *upipe)
{
    struct upipe_srths *upipe_srths = upipe_srths_from_upipe(upipe);

    upipe_throw_dead(upipe);

    free(upipe_srths->uri);
    upipe_srths_clean_output(upipe);
    upipe_srths_clean_ubuf_mgr(upipe);
    upipe_srths_clean_uref_mgr(upipe);
    upipe_srths_clean_urefcount(upipe);
    upipe_srths_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_srths_mgr = {
    .refcount = NULL,
    .signature = UPIPE_SRT_HANDSHAKE_SIGNATURE,

    .upipe_alloc = upipe_srths_alloc,
    .upipe_input = NULL,
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
