/*
 * Copyright (C) 2017 OpenHeadend S.A.R.L.
 *
 * Authors: Arnaud de Turckheim
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

/** @file @short Upipe module that notifies for all known ES PIDs.
 */
#ifndef _UPIPE_DVBCSA_UPIPE_DVBCSA_SPLIT_H_
#define _UPIPE_DVBCSA_UPIPE_DVBCSA_SPLIT_H_
#ifdef __cplusplus
extern "C" {
#endif

#define UPIPE_DVBCSA_SPLIT_SIGNATURE    UBASE_FOURCC('c','s','a','s')

/** @This enumarates the privates events for dvbcsa pipes. */
enum uprobe_dvbcsa_split_event {
    /** sentinel */
    UPROBE_DVBCSA_SPLIT_SENTINEL = UPROBE_LOCAL,

    /** pid added (uint64_t) */
    UPROBE_DVBCSA_SPLIT_ADD_PID,
    /** pid removed (uint64_t) */
    UPROBE_DVBCSA_SPLIT_DEL_PID,
};

/** @This returns the dvbcsa split pipe manager.
 *
 * @return a pointer to the manager
 */
struct upipe_mgr *upipe_dvbcsa_split_mgr_alloc(void);

#ifdef __cplusplus
}
#endif
#endif