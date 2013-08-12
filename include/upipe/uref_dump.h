/*
 * Copyright (C) 2013 OpenHeadend S.A.R.L.
 *
 * Authors: Christophe Massiot
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
 * @short Upipe uref dumping for debug purposes
 */

#ifndef _UPIPE_UREF_DUMP_H_
/** @hidden */
#define _UPIPE_UREF_DUMP_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <upipe/ubase.h>
#include <upipe/uref.h>
#include <upipe/udict_dump.h>
#include <upipe/uprobe.h>

#include <stdint.h>
#include <inttypes.h>

/** @internal @This dumps the content of a uref for debug purposes.
 *
 * @param uref pointer to the uref
 * @param uprobe pipe module printing the messages
 */
static inline void uref_dump(struct uref *uref, struct uprobe *uprobe)
{
    if (uref->ubuf != NULL)
        uprobe_dbg_va(uprobe, NULL, "dumping uref %p pointing to ubuf %p",
                      uref, uref->ubuf);
    else
        uprobe_dbg_va(uprobe, NULL, "dumping uref %p", uref);

#define UREF_DUMP_VOID(name, member)                                        \
    if (uref->flags & member)                                               \
        uprobe_dbg_va(uprobe, NULL, " - \"" name "\" [void]");
    UREF_DUMP_VOID("f.end", UREF_FLAG_FLOW_END)
    UREF_DUMP_VOID("f.disc", UREF_FLAG_FLOW_DISC)
    UREF_DUMP_VOID("b.start", UREF_FLAG_BLOCK_START)
#undef UREF_DUMP_VOID

#define UREF_DUMP_UNSIGNED(name, member)                                    \
    if (uref->member != UINT64_MAX)                                         \
        uprobe_dbg_va(uprobe, NULL, " - \"" name "\" [unsigned]: %"PRIu64,  \
                      uref->member);
    UREF_DUMP_UNSIGNED("k.systime", systime)
    UREF_DUMP_UNSIGNED("k.systime_rap", systime_rap)
    UREF_DUMP_UNSIGNED("k.pts", pts)
    UREF_DUMP_UNSIGNED("k.pts.orig", pts_orig)
    UREF_DUMP_UNSIGNED("k.pts.sys", pts_sys)
    UREF_DUMP_UNSIGNED("k.dts", dts)
    UREF_DUMP_UNSIGNED("k.dts.orig", dts_orig)
    UREF_DUMP_UNSIGNED("k.dts.sys", dts_sys)
    UREF_DUMP_UNSIGNED("k.vbv_delay", vbv_delay)
#undef UREF_DUMP_UNSIGNED

    if (uref->udict != NULL)
        udict_dump(uref->udict, uprobe);
}

#ifdef __cplusplus
}
#endif
#endif
