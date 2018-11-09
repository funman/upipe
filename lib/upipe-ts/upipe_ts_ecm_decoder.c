/*
 * Copyright (C) 2018 Open Broadcast Systems Ltd
 *
 * Authors: Rafaël Carré
 *
 * This ts is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation; either version 2.1 of the License, or
 * (at your option) any later version.
 *
 * This ts is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this ts; if not, write to the Free Software Foundation,
 * Inc., 51 Franklin Street, Fifth Floor, Boston MA 02110-1301, USA.
 */

/** @file
 * @short Upipe module decoding the entitlement management message table
 * Normative references:
 *   EBU TECH 3292-s1
 */

#include <upipe/ubase.h>
#include <upipe/ulist.h>
#include <upipe/uclock.h>
#include <upipe/uprobe.h>
#include <upipe/uref.h>
#include <upipe/uref_flow.h>
#include <upipe/uref_block.h>
#include <upipe/ubuf.h>
#include <upipe/upipe.h>
#include <upipe/upipe_helper_upipe.h>
#include <upipe/upipe_helper_urefcount.h>
#include <upipe/upipe_helper_void.h>
#include <upipe/upipe_helper_output.h>
#include <upipe/upipe_helper_ubuf_mgr.h>
#include <upipe/upipe_helper_flow_def.h>
#include <upipe-ts/upipe_ts_ecm_decoder.h>
#include <upipe-ts/uref_ts_flow.h>
#include "upipe_ts_psi_decoder.h"

#include <bitstream/mpeg/psi.h>
#include <bitstream/mpeg/psi/desc_09.h>
#include <bitstream/dvb/si.h>
#include <bitstream/ebu/biss.h>

#include <gcrypt.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/** we only accept TS packets */
#define EXPECTED_FLOW_DEF "block.mpegtspsi.mpegtsecm."

/** @hidden */
static int upipe_ts_ecmd_check(struct upipe *upipe, struct uref *flow_format);

/** @internal @This is the private context of a ts_ecmd pipe. */
struct upipe_ts_ecmd {
    /** refcount management structure */
    struct urefcount urefcount;

    /** ubuf manager */
    struct ubuf_mgr *ubuf_mgr;
    /** flow format packet */
    struct uref *flow_format;
    /** ubuf manager request */
    struct urequest ubuf_mgr_request;

    /** pipe acting as output */
    struct upipe *output;
    /** output flow definition */
    struct uref *flow_def;
    /** output state */
    enum upipe_helper_output_state output_state;
    /** list of output requests */
    struct uchain request_list;
    /** input flow definition */
    struct uref *flow_def_input;
    /** attributes in the sequence header */
    struct uref *flow_def_attr;

    gcry_sexp_t key;

    /** currently in effect ECM table */
    UPIPE_TS_PSID_TABLE_DECLARE(ecm);
    /** ECM table being gathered */
    UPIPE_TS_PSID_TABLE_DECLARE(next_ecm);

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_ts_ecmd, upipe, UPIPE_TS_ECMD_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_ts_ecmd, urefcount, upipe_ts_ecmd_free)
UPIPE_HELPER_VOID(upipe_ts_ecmd)
UPIPE_HELPER_OUTPUT(upipe_ts_ecmd, output, flow_def, output_state, request_list)
UPIPE_HELPER_UBUF_MGR(upipe_ts_ecmd, ubuf_mgr, flow_format, ubuf_mgr_request,
                      upipe_ts_ecmd_check,
                      upipe_ts_ecmd_register_output_request,
                      upipe_ts_ecmd_unregister_output_request)
UPIPE_HELPER_FLOW_DEF(upipe_ts_ecmd, flow_def_input, flow_def_attr)

/** @internal @This alloecmes a ts_ecmd pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe alloecmor
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of alloecmion error
 */
static struct upipe *upipe_ts_ecmd_alloc(struct upipe_mgr *mgr,
                                         struct uprobe *uprobe,
                                         uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_ts_ecmd_alloc_void(mgr, uprobe, signature,
                                                   args);
    if (unlikely(upipe == NULL))
        return NULL;

    struct upipe_ts_ecmd *upipe_ts_ecmd = upipe_ts_ecmd_from_upipe(upipe);

    upipe_ts_ecmd->key = NULL;

    upipe_ts_ecmd_init_urefcount(upipe);
    upipe_ts_ecmd_init_output(upipe);
    upipe_ts_ecmd_init_ubuf_mgr(upipe);
    upipe_ts_ecmd_init_flow_def(upipe);
    upipe_ts_psid_table_init(upipe_ts_ecmd->ecm);
    upipe_ts_psid_table_init(upipe_ts_ecmd->next_ecm);
    upipe_throw_ready(upipe);
    return upipe;
}

/** @internal @This validates the next ECM.
 *
 * @param upipe description structure of the pipe
 * @return false if the ECM is invalid
 */
static bool upipe_ts_ecmd_table_validate(struct upipe *upipe)
{
    struct upipe_ts_ecmd *upipe_ts_ecmd = upipe_ts_ecmd_from_upipe(upipe);
    upipe_ts_psid_table_foreach (upipe_ts_ecmd->next_ecm, section_uref) {
        const uint8_t *section;
        int size = -1;
        if (unlikely(!ubase_check(uref_block_read(section_uref, 0, &size,
                                                  &section))))
            return false;

        if (/*!ecm_validate(section) || */!psi_check_crc(section)) {
            uref_block_unmap(section_uref, 0);
            return false;
        }

        uref_block_unmap(section_uref, 0);
    }
    return true;
}

/** @internal @This is a helper function to parse descriptors and import
 * the relevant ones into flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet to fill in
 * @param descl pointer to descriptor list
 * @param desclength length of the descriptor list
 * @return an error code
 */
static void upipe_ts_ecmd_parse_descs(struct upipe *upipe,
                                      struct uref *flow_def,
                                      const uint8_t *descl, uint16_t desclength)
{
    const uint8_t *desc;
    int j = 0;
    /* cast needed because biTStream expects an uint8_t * (but doesn't write
     * to it */
    while ((desc = descl_get_desc((uint8_t *)descl, desclength, j++)) != NULL) {
        bool copy = false;
        switch (desc_get_tag(desc)) {
            default:
                copy = true;
                break;
        }

        if (copy) {
//            UBASE_FATAL(upipe, uref_ts_flow_add_ecm_descriptor(flow_def,
//                        desc, desc_get_length(desc) + DESC_HEADER_SIZE))
        }
    }
}

/** @internal @This is a helper function to parse session data descriptors and
 * import the relevant ones into flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet to fill in
 * @param descl pointer to descriptor list
 * @param desclength length of the descriptor list
 * @return an error code
 */
static void upipe_ts_ecmd_parse_sd_descs(struct upipe *upipe,
                                      struct uref *flow_def,
                                      const uint8_t *descl, uint16_t desclength)
{
    const uint8_t *desc;
    int j = 0;

    bool prevent_descrambled_forward = false;
    bool prevent_decoded_forward = false;
    bool insert_watermark = false;

    /* cast needed because biTStream expects an uint8_t * (but doesn't write
     * to it */
    while ((desc = descl_get_desc((uint8_t *)descl, desclength, j++)) != NULL) {
        bool copy = false;
        bool valid = true;
        uint16_t length = desc_get_length(desc);
        switch (desc_get_tag(desc)) {
            case 0x81:
                valid = length == 17;
                if (!valid)
                    break;
                uint8_t type = desc[DESC_HEADER_SIZE];
                bool odd = type & 1;
                type >>= 1;
                valid = type == 0; // AES-128-CBC
                if (!valid)
                    break;
                const uint8_t *key = &desc[DESC_HEADER_SIZE+1];
                upipe_notice_va(upipe, "%s key : %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
                    odd ? "odd" : "even",
                    key[0], key[1], key[2], key[3], key[4], key[5], key[6], key[7],
                    key[8], key[9], key[10], key[11], key[12], key[13], key[14], key[15]
                    );
                break;
            case 0x82:
                valid = length == 1;
                if (!valid)
                    break;
                uint8_t flags = desc[DESC_HEADER_SIZE];
                prevent_descrambled_forward = flags & (1 << 7);
                prevent_decoded_forward = flags & (1 << 6);
                insert_watermark = flags & (1 << 5);
                break;
            default:
                copy = true;
                break;
        }

        if (!valid)
            upipe_warn_va(upipe, "invalid session data descriptor 0x%x",
                    desc_get_tag(desc));

        if (copy) {
//            UBASE_FATAL(upipe, uref_ts_flow_add_ecm_descriptor(flow_def,
//                        desc, desc_get_length(desc) + DESC_HEADER_SIZE))
        }
    }
}

/** @internal @This parses a new PSI section.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_ts_ecmd_input(struct upipe *upipe, struct uref *uref,
                                struct upump **upump_p)
{
    struct upipe_ts_ecmd *upipe_ts_ecmd = upipe_ts_ecmd_from_upipe(upipe);
    assert(upipe_ts_ecmd->flow_def_input != NULL);

    if (!upipe_ts_psid_table_section(upipe_ts_ecmd->next_ecm, uref))
        return;

    if (upipe_ts_psid_table_validate(upipe_ts_ecmd->ecm) &&
        upipe_ts_psid_table_compare(upipe_ts_ecmd->ecm,
                                    upipe_ts_ecmd->next_ecm)) {
        /* Identical ECM. */
        upipe_ts_psid_table_clean(upipe_ts_ecmd->next_ecm);
        upipe_ts_psid_table_init(upipe_ts_ecmd->next_ecm);
        return;
    }

    if (!ubase_check(upipe_ts_psid_table_merge(upipe_ts_ecmd->next_ecm,
                                               upipe_ts_ecmd->ubuf_mgr)) ||
        !upipe_ts_ecmd_table_validate(upipe)) {
        upipe_warn(upipe, "invalid ECM section received");
        upipe_ts_psid_table_clean(upipe_ts_ecmd->next_ecm);
        upipe_ts_psid_table_init(upipe_ts_ecmd->next_ecm);
        return;
    }

    struct uref *flow_def = upipe_ts_ecmd_alloc_flow_def_attr(upipe);
    if (unlikely(flow_def == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        uref_free(uref);
        return;
    }
    UBASE_FATAL(upipe, uref_flow_set_def(flow_def, "void."))
    upipe_ts_psid_table_foreach (upipe_ts_ecmd->next_ecm, section_uref) {
        const uint8_t *section;
        int size = -1;
        if (unlikely(!ubase_check(uref_block_read(section_uref, 0, &size,
                                                  &section))))
            continue;

    // TODO : move to bitstream

//        upipe_ts_ecmd_parse_descs(upipe, flow_def,
//                ecm_get_descl_const(section), ecm_get_desclength(section));
//        assert(size == 6
        assert(size == 65);
        uint16_t esid = (section[3] << 8) | section[4];
        uint16_t onid = (section[8] << 8) | section[9];
        uint8_t cipher = section[10] >> 5;
        assert(cipher == 0); // AES
        uint16_t dl = descs_get_length(&section[10]);
        assert(dl == 0);
        bool odd = section[12] & 0x80;
        const uint8_t *iv = &section[13+0];
        upipe_dbg_va(upipe, "ESID %04x ONID %04x", esid, onid);
        upipe_dbg_va(upipe, "IV %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            iv[0], iv[1], iv[2], iv[3], iv[4], iv[5], iv[6], iv[7],
            iv[8], iv[9], iv[10], iv[11], iv[12], iv[13], iv[14], iv[15]);
        const uint8_t *even_k  = &section[13+16];
        upipe_dbg_va(upipe, "EVEN K %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            even_k[0], even_k[1], even_k[2], even_k[3], even_k[4], even_k[5], even_k[6], even_k[7],
            even_k[8], even_k[9], even_k[10], even_k[11], even_k[12], even_k[13], even_k[14], even_k[15]);
        const uint8_t *odd_k  = &section[13+16*2];
        upipe_dbg_va(upipe, "ODD K %02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x%02x",
            odd_k[0], odd_k[1], odd_k[2], odd_k[3], odd_k[4], odd_k[5], odd_k[6], odd_k[7],
            odd_k[8], odd_k[9], odd_k[10], odd_k[11], odd_k[12], odd_k[13], odd_k[14], odd_k[15]);


        uref_block_unmap(section_uref, 0);
    }

    /* Switch tables. */
    if (upipe_ts_psid_table_validate(upipe_ts_ecmd->ecm))
        upipe_ts_psid_table_clean(upipe_ts_ecmd->ecm);
    upipe_ts_psid_table_copy(upipe_ts_ecmd->ecm, upipe_ts_ecmd->next_ecm);
    upipe_ts_psid_table_init(upipe_ts_ecmd->next_ecm);

    flow_def = upipe_ts_ecmd_store_flow_def_attr(upipe, flow_def);
    if (unlikely(flow_def == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        uref_free(uref);
        return;
    }
    upipe_ts_ecmd_store_flow_def(upipe, flow_def);
    /* Force sending flow def */
    upipe_ts_ecmd_output(upipe, NULL, upump_p);
}

/** @internal @This receives an ubuf manager.
 *
 * @param upipe description structure of the pipe
 * @param flow_format amended flow format
 * @return an error code
 */
static int upipe_ts_ecmd_check(struct upipe *upipe, struct uref *flow_format)
{
    if (flow_format != NULL) {
        flow_format = upipe_ts_ecmd_store_flow_def_input(upipe, flow_format);
        if (flow_format != NULL) {
            upipe_ts_ecmd_store_flow_def(upipe, flow_format);
            /* Force sending flow def */
            upipe_ts_ecmd_output(upipe, NULL, NULL);
        }
    }

    return UBASE_ERR_NONE;
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_ts_ecmd_set_flow_def(struct upipe *upipe,
                                      struct uref *flow_def)
{
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, EXPECTED_FLOW_DEF))
    struct uref *flow_def_dup;
    if (unlikely((flow_def_dup = uref_dup(flow_def)) == NULL)) {
        upipe_throw_fatal(upipe, UBASE_ERR_ALLOC);
        return UBASE_ERR_ALLOC;
    }
    upipe_ts_ecmd_demand_ubuf_mgr(upipe, flow_def_dup);
    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_ts_ecmd_control(struct upipe *upipe, int command, va_list args)
{
    UBASE_HANDLED_RETURN(upipe_ts_ecmd_control_output(upipe, command, args));
    switch (command) {
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_ts_ecmd_set_flow_def(upipe, flow_def);
        }

        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_ts_ecmd_free(struct upipe *upipe)
{
    upipe_throw_dead(upipe);

    struct upipe_ts_ecmd *upipe_ts_ecmd = upipe_ts_ecmd_from_upipe(upipe);


    upipe_ts_psid_table_clean(upipe_ts_ecmd->ecm);
    upipe_ts_psid_table_clean(upipe_ts_ecmd->next_ecm);
    upipe_ts_ecmd_clean_output(upipe);
    upipe_ts_ecmd_clean_ubuf_mgr(upipe);
    upipe_ts_ecmd_clean_flow_def(upipe);
    upipe_ts_ecmd_clean_urefcount(upipe);
    upipe_ts_ecmd_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_ts_ecmd_mgr = {
    .refcount = NULL,
    .signature = UPIPE_TS_ECMD_SIGNATURE,

    .upipe_alloc = upipe_ts_ecmd_alloc,
    .upipe_input = upipe_ts_ecmd_input,
    .upipe_control = upipe_ts_ecmd_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all ts_ecmd pipes.
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_ts_ecmd_mgr_alloc(void)
{
    return &upipe_ts_ecmd_mgr;
}
