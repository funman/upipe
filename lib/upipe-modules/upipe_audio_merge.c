/*
 * Copyright (C) 2015 Open Broadcast Systems Ltd.
 *
 * Authors: Kieran Kunhya
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */

/** @file
 * @short Upipe module merging audio packets into a single buffer
 */

#include <upipe/ubase.h>
#include <upipe/ulist.h>
#include <upipe/uprobe.h>
#include <upipe/uref.h>
#include <upipe/ubuf.h>
#include <upipe/upipe.h>
#include <upipe/uclock.h>
#include <upipe/uref_sound.h>
#include <upipe/uref_sound_flow.h>
#include <upipe/upipe_helper_upipe.h>
#include <upipe/upipe_helper_urefcount.h>
#include <upipe/upipe_helper_void.h>
#include <upipe/upipe_helper_flow.h>
#include <upipe/upipe_helper_input.h>
#include <upipe/upipe_helper_output.h>
#include <upipe/upipe_helper_subpipe.h>
#include <upipe/upipe_helper_ubuf_mgr.h>
#include <upipe/upipe_helper_uclock.h>
#include <upipe/upipe_helper_upump_mgr.h>
#include <upipe/upipe_helper_upump.h>
#include <upipe-modules/upipe_audio_merge.h>

#include <stdlib.h>
#include <stdbool.h>
#include <stdarg.h>
#include <string.h>
#include <assert.h>

/** @hidden */
static bool upipe_audio_merge_sub_output(struct upipe *upipe, struct uref *uref,
                                         struct upump **upump_p);

/** @hidden */
static int upipe_audio_merge_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of an audio_merge pipe. */
struct upipe_audio_merge {
    /** real refcount management structure */
    struct urefcount urefcount_real;
    /** refcount management structure exported to the public structure */
    struct urefcount urefcount;

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

    /** list of input subpipes */
    struct uchain inputs;

    /** output pipe */
    struct upipe *output;
    /** flow_definition packet */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;

    /** manager to create input subpipes */
    struct upipe_mgr sub_mgr;

    /** upump manager */
    struct upump_mgr *upump_mgr;
    /** watcher */
    struct upump *upump;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_audio_merge, upipe, UPIPE_AUDIO_MERGE_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_audio_merge, urefcount, upipe_audio_merge_no_input)
UPIPE_HELPER_VOID(upipe_audio_merge)
UPIPE_HELPER_OUTPUT(upipe_audio_merge, output, flow_def, output_state, request_list)

UPIPE_HELPER_UBUF_MGR(upipe_audio_merge, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_audio_merge_check,
                      upipe_audio_merge_register_output_request,
                      upipe_audio_merge_unregister_output_request)

UPIPE_HELPER_UCLOCK(upipe_audio_merge, uclock, uclock_request, upipe_audio_merge_check,
                    upipe_audio_merge_register_output_request,
                    upipe_audio_merge_unregister_output_request)

UPIPE_HELPER_UPUMP_MGR(upipe_audio_merge, upump_mgr);
UPIPE_HELPER_UPUMP(upipe_audio_merge, upump, upump_mgr);

UBASE_FROM_TO(upipe_audio_merge, urefcount, urefcount_real, urefcount_real)

/** @hidden */
static void upipe_audio_merge_free(struct urefcount *urefcount_real);

/** @internal @This is the private context of an output of an audio_merge
 * pipe. */
struct upipe_audio_merge_sub {
    /** refcount management structure */
    struct urefcount urefcount;
    /** structure for double-linked lists */
    struct uchain uchain;

    /** flow_definition packet */
    struct uref *flow_def;

    /** temporary uref storage */
    struct uchain urefs;
    /** nb urefs in storage */
    unsigned int nb_urefs;
    /** max urefs in storage */
    unsigned int max_urefs;
    /** list of blockers */
    struct uchain blockers;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_audio_merge_sub, upipe,
                   UPIPE_AUDIO_MERGE_INPUT_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_audio_merge_sub, urefcount,
                       upipe_audio_merge_sub_free)
UPIPE_HELPER_INPUT(upipe_audio_merge_sub, urefs, nb_urefs, max_urefs, blockers, upipe_audio_merge_sub_output)
UPIPE_HELPER_FLOW(upipe_audio_merge_sub, "sound.")

UPIPE_HELPER_SUBPIPE(upipe_audio_merge, upipe_audio_merge_sub, input,
                     sub_mgr, inputs, uchain)

/** @internal @This allocates an output subpipe of an audio_merge pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_audio_merge_sub_alloc(struct upipe_mgr *mgr,
                                                 struct uprobe *uprobe,
                                                 uint32_t signature, va_list args)
{
    struct uref *flow_def;
    struct upipe *upipe = upipe_audio_merge_sub_alloc_flow(mgr,
                            uprobe, signature, args, &flow_def);
    if (unlikely(upipe == NULL)) {
        return NULL;
    }

    struct upipe_audio_merge_sub *upipe_audio_merge_sub =
                            upipe_audio_merge_sub_from_upipe(upipe);
    upipe_audio_merge_sub_init_urefcount(upipe);
    upipe_audio_merge_sub_init_input(upipe);
    upipe_audio_merge_sub_init_sub(upipe);
    upipe_throw_ready(upipe);
    return upipe;
}

static int upipe_audio_merge_sub_set_flow_def(struct upipe *upipe,
                                          struct uref *flow_def)
{
    struct upipe_audio_merge *upipe_audio_merge =
        upipe_audio_merge_from_sub_mgr(upipe->mgr);
    struct upipe_audio_merge_sub *upipe_audio_merge_sub =
        upipe_audio_merge_sub_from_upipe(upipe);

    if (flow_def == NULL)
        return UBASE_ERR_INVALID;

    // FIXME check flow def

    flow_def = uref_dup(flow_def);
    UBASE_ALLOC_RETURN(flow_def)
    upipe_input(upipe, flow_def, NULL);
    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on an input subpipe of an
 *  audio_merge pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_audio_merge_sub_control(struct upipe *upipe,
                                         int command, va_list args)
{
    switch (command) {
#if 0
        case UPIPE_GET_FLOW_DEF: {
            struct uref **p = va_arg(args, struct uref **);
            return upipe_audio_merge_sub_get_flow_def(upipe, p);
        }
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_audio_merge_sub_set_flow_def(upipe, flow_def);
        }
#endif
        case UPIPE_SUB_GET_SUPER: {
            struct upipe **p = va_arg(args, struct upipe **);
            return upipe_audio_merge_sub_get_super(upipe, p);
        }

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @internal @This receives data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static bool upipe_audio_merge_sub_output(struct upipe *upipe, struct uref *uref,
                                         struct upump **upump_p)
{
    struct upipe_audio_merge *upipe_audio_merge =
                              upipe_audio_merge_from_upipe(upipe);
    struct uchain *uchain;
    if (unlikely(!upipe_audio_merge->flow_def)) {
        upipe_warn(upipe, "received uref before flow definition, droppping");
        uref_free(uref);
        return false;
    }

    // buffer frames and start timer if encessary

    return true;
}

/** @internal @This handles output data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to upump structure
 */
static void upipe_audio_merge_sub_input(struct upipe *upipe, struct uref *uref,
                                      struct upump **upump_p)
{
    struct upipe_audio_merge *upipe_audio_merge =
        upipe_audio_merge_from_sub_mgr(upipe->mgr);

     upipe_audio_merge_sub_output(upipe, uref, upump_p);
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_audio_merge_sub_free(struct upipe *upipe)
{
    struct upipe_audio_merge_sub *upipe_audio_merge_sub =
                              upipe_audio_merge_sub_from_upipe(upipe);
    upipe_throw_dead(upipe);

    upipe_audio_merge_sub_clean_input(upipe);
    upipe_audio_merge_sub_clean_sub(upipe);
    upipe_audio_merge_sub_clean_urefcount(upipe);
    upipe_audio_merge_sub_free_flow(upipe);
}

/** @internal @This initializes the output manager for an audio_merge sub pipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_audio_merge_init_sub_mgr(struct upipe *upipe)
{
    struct upipe_audio_merge *upipe_audio_merge =
                              upipe_audio_merge_from_upipe(upipe);
    struct upipe_mgr *sub_mgr = &upipe_audio_merge->sub_mgr;
    sub_mgr->refcount = upipe_audio_merge_to_urefcount_real(upipe_audio_merge);
    sub_mgr->signature = UPIPE_AUDIO_MERGE_INPUT_SIGNATURE;
    sub_mgr->upipe_alloc = upipe_audio_merge_sub_alloc;
    sub_mgr->upipe_input = upipe_audio_merge_sub_input;
    sub_mgr->upipe_control = upipe_audio_merge_sub_control;
    sub_mgr->upipe_mgr_control = NULL;
}

/** @internal @This allocates an audio_merge pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_audio_merge_alloc(struct upipe_mgr *mgr,
                                             struct uprobe *uprobe,
                                             uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_audio_merge_alloc_void(mgr,
                                    uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

    struct upipe_audio_merge *upipe_audio_merge =
                              upipe_audio_merge_from_upipe(upipe);
    upipe_audio_merge_init_urefcount(upipe);
    urefcount_init(upipe_audio_merge_to_urefcount_real(upipe_audio_merge),
                   upipe_audio_merge_free);

    upipe_audio_merge_init_upump_mgr(upipe);
    upipe_audio_merge_init_upump(upipe);
    upipe_audio_merge_init_ubuf_mgr(upipe);
    upipe_audio_merge_init_uclock(upipe);
    upipe_audio_merge_init_output(upipe);
    upipe_audio_merge_init_sub_mgr(upipe);
    upipe_audio_merge_init_sub_inputs(upipe);

    upipe_audio_merge->flow_def = NULL;
    upipe_throw_ready(upipe);
    return upipe;
}

/** @internal @This receives a provided ubuf manager.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_audio_merge_check(struct upipe *upipe, struct uref *flow_format)
{
    struct upipe_audio_merge *upipe_audio_merge = upipe_audio_merge_from_upipe(upipe);
    if (flow_format != NULL)
        upipe_audio_merge_store_flow_def(upipe, flow_format);

    if (upipe_audio_merge->flow_def == NULL)
        return UBASE_ERR_NONE;

    // FIXME this is broke

    return UBASE_ERR_NONE;
}

/** @internal @This changes the flow definition on all outputs.
 *
 * @param upipe description structure of the pipe
 * @param flow_def new flow definition
 * @return an error code
 */
static int upipe_audio_merge_set_flow_def(struct upipe *upipe,
                                          struct uref *flow_def)
{
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, "sound."))
    UBASE_RETURN(uref_sound_flow_match_planes(flow_def, 2, 32))
    struct uref *flow_def_audio_merge;

    if ((flow_def_audio_merge = uref_dup(flow_def)) == NULL) {
        return UBASE_ERR_ALLOC;
    }

    struct upipe_audio_merge *upipe_audio_merge =
                              upipe_audio_merge_from_upipe(upipe);
    if (upipe_audio_merge->flow_def != NULL)
        uref_free(upipe_audio_merge->flow_def);
    upipe_audio_merge->flow_def = flow_def_audio_merge;

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on an audio_merge pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_audio_merge_control(struct upipe *upipe,
                                     int command, va_list args)
{
    switch (command) {
        case UPIPE_ATTACH_UPUMP_MGR:
            upipe_audio_merge_set_upump(upipe, NULL);
            return upipe_audio_merge_attach_upump_mgr(upipe);
        case UPIPE_ATTACH_UCLOCK:
            upipe_audio_merge_set_upump(upipe, NULL);
            upipe_audio_merge_require_uclock(upipe);
            return UBASE_ERR_NONE;
        case UPIPE_REGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            return upipe_throw_provide_request(upipe, request);
        }
        case UPIPE_UNREGISTER_REQUEST:
            return UBASE_ERR_NONE;
        case UPIPE_GET_OUTPUT: {
            struct upipe **p = va_arg(args, struct upipe **);
            return upipe_audio_merge_get_output(upipe, p);
        }
        case UPIPE_SET_OUTPUT: {
            struct upipe *output = va_arg(args, struct upipe *);
            return upipe_audio_merge_set_output(upipe, output);
        }
        case UPIPE_GET_FLOW_DEF: {
            struct uref **p = va_arg(args, struct uref **);
            return upipe_audio_merge_get_flow_def(upipe, p);
        }
        case UPIPE_SET_FLOW_DEF: {
            struct uref *uref = va_arg(args, struct uref *);
            return upipe_audio_merge_set_flow_def(upipe, uref);
        }
        case UPIPE_GET_SUB_MGR: {
            struct upipe_mgr **p = va_arg(args, struct upipe_mgr **);
            return upipe_audio_merge_get_sub_mgr(upipe, p);
        }
        case UPIPE_ITERATE_SUB: {
            struct upipe **p = va_arg(args, struct upipe **);
            return upipe_audio_merge_iterate_sub(upipe, p);
        }

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @This frees a upipe.
 *
 * @param urefcount_real pointer to urefcount_real structure
 */
static void upipe_audio_merge_free(struct urefcount *urefcount_real)
{
    struct upipe_audio_merge *upipe_audio_merge =
           upipe_audio_merge_from_urefcount_real(urefcount_real);
    struct upipe *upipe = upipe_audio_merge_to_upipe(upipe_audio_merge);
    upipe_throw_dead(upipe);
    upipe_audio_merge_clean_uclock(upipe);
    upipe_audio_merge_clean_upump(upipe);
    upipe_audio_merge_clean_upump_mgr(upipe);
    upipe_audio_merge_clean_output(upipe);
    upipe_audio_merge_clean_ubuf_mgr(upipe);
    upipe_audio_merge_clean_sub_inputs(upipe);
    if (upipe_audio_merge->flow_def != NULL)
        uref_free(upipe_audio_merge->flow_def);
    urefcount_clean(urefcount_real);
    upipe_audio_merge_clean_urefcount(upipe);
    upipe_audio_merge_free_void(upipe);
}

/** @This is called when there is no external reference to the pipe anymore.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_audio_merge_no_input(struct upipe *upipe)
{
    struct upipe_audio_merge *upipe_audio_merge =
                              upipe_audio_merge_from_upipe(upipe);
    urefcount_release(upipe_audio_merge_to_urefcount_real(upipe_audio_merge));
}

/** audio_merge module manager static descriptor */
static struct upipe_mgr upipe_audio_merge_mgr = {
    .refcount = NULL,
    .signature = UPIPE_AUDIO_MERGE_SIGNATURE,

    .upipe_alloc = upipe_audio_merge_alloc,
    .upipe_input = NULL,
    .upipe_control = upipe_audio_merge_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all audio_merge pipes.
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_audio_merge_mgr_alloc(void)
{
    return &upipe_audio_merge_mgr;
}
