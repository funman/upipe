/*
 * Copyright (C) 2012-2013 OpenHeadend S.A.R.L.
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
 * @short unit tests for file source and sink pipes
 */

#undef NDEBUG

#include <upipe/uprobe.h>
#include <upipe/uprobe_stdio.h>
#include <upipe/uprobe_prefix.h>
#include <upipe/uprobe_log.h>
#include <upipe/uclock.h>
#include <upipe/uclock_std.h>
#include <upipe/umem.h>
#include <upipe/umem_alloc.h>
#include <upipe/udict.h>
#include <upipe/udict_inline.h>
#include <upipe/ubuf.h>
#include <upipe/ubuf_block.h>
#include <upipe/ubuf_block_mem.h>
#include <upipe/uref.h>
#include <upipe/uref_std.h>
#include <upipe/upump.h>
#include <upump-ev/upump_ev.h>
#include <upipe/upipe.h>
#include <upipe-modules/upipe_file_source.h>
#include <upipe-modules/upipe_file_sink.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <assert.h>

#include <ev.h>

#define UDICT_POOL_DEPTH 10
#define UREF_POOL_DEPTH 10
#define UBUF_POOL_DEPTH 10
#define UPUMP_POOL 1
#define UPUMP_BLOCKER_POOL 1
#define READ_SIZE 4096
#define UPROBE_LOG_LEVEL UPROBE_LOG_DEBUG

static void usage(const char *argv0) {
    fprintf(stdout, "Usage: %s [-d <delay>] [-a|-o] <source file> <sink file>\n", argv0);
    fprintf(stdout, "-a : append\n");
    fprintf(stdout, "-o : overwrite\n");
    exit(EXIT_FAILURE);
}

/** definition of our uprobe */
static bool catch(struct uprobe *uprobe, struct upipe *upipe,
                  enum uprobe_event event, va_list args)
{
    switch (event) {
        default:
            assert(0);
            break;
        case UPROBE_READY:
        case UPROBE_DEAD:
        case UPROBE_SOURCE_END:
        case UPROBE_NEW_FLOW_DEF:
            break;
    }
    return true;
}

int main(int argc, char *argv[])
{
    const char *src_file, *sink_file;
    uint64_t delay = 0;
    enum upipe_fsink_mode mode = UPIPE_FSINK_CREATE;
    int opt;
    while ((opt = getopt(argc, argv, "d:ao")) != -1) {
        switch (opt) {
            case 'd':
                delay = atoi(optarg);
                break;
            case 'a':
                mode = UPIPE_FSINK_APPEND;
                break;
            case 'o':
                mode = UPIPE_FSINK_OVERWRITE;
                break;
            default:
                usage(argv[0]);
        }
    }
    if (optind >= argc -1)
        usage(argv[0]);
    src_file = argv[optind++];
    sink_file = argv[optind++];

    struct ev_loop *loop = ev_default_loop(0);
    struct umem_mgr *umem_mgr = umem_alloc_mgr_alloc();
    assert(umem_mgr != NULL);
    struct udict_mgr *udict_mgr = udict_inline_mgr_alloc(UDICT_POOL_DEPTH,
                                                         umem_mgr, -1, -1);
    assert(udict_mgr != NULL);
    struct uref_mgr *uref_mgr = uref_std_mgr_alloc(UREF_POOL_DEPTH, udict_mgr,
                                                   0);
    assert(uref_mgr != NULL);
    struct ubuf_mgr *ubuf_mgr = ubuf_block_mem_mgr_alloc(UBUF_POOL_DEPTH,
                                                         UBUF_POOL_DEPTH,
                                                         umem_mgr, -1, -1,
                                                         -1, 0);
    assert(ubuf_mgr != NULL);
    struct upump_mgr *upump_mgr = upump_ev_mgr_alloc(loop, UPUMP_POOL,
                                                     UPUMP_BLOCKER_POOL);
    assert(upump_mgr != NULL);
    struct uclock *uclock = uclock_std_alloc(0);
    assert(uclock != NULL);
    struct uprobe uprobe;
    uprobe_init(&uprobe, catch, NULL);
    struct uprobe *uprobe_stdio = uprobe_stdio_alloc(&uprobe, stdout,
                                                     UPROBE_LOG_LEVEL);
    assert(uprobe_stdio != NULL);
    struct uprobe *log = uprobe_log_alloc(uprobe_stdio, UPROBE_LOG_DEBUG);
    assert(log != NULL);

    struct upipe_mgr *upipe_fsrc_mgr = upipe_fsrc_mgr_alloc();
    assert(upipe_fsrc_mgr != NULL);
    struct upipe *upipe_fsrc = upipe_void_alloc(upipe_fsrc_mgr,
            uprobe_pfx_adhoc_alloc(log, UPROBE_LOG_LEVEL, "file source"));
    assert(upipe_fsrc != NULL);
    assert(upipe_set_upump_mgr(upipe_fsrc, upump_mgr));
    assert(upipe_set_uref_mgr(upipe_fsrc, uref_mgr));
    assert(upipe_set_ubuf_mgr(upipe_fsrc, ubuf_mgr));
    assert(upipe_source_set_read_size(upipe_fsrc, READ_SIZE));
    if (delay)
        assert(upipe_set_uclock(upipe_fsrc, uclock));
    assert(upipe_set_uri(upipe_fsrc, src_file));
    uint64_t size;
    if (upipe_fsrc_get_size(upipe_fsrc, &size))
        fprintf(stdout, "source file has size %"PRIu64"\n", size);
    else
        fprintf(stdout, "source path is not a regular file\n");

    struct uref *uref;
    assert(upipe_get_flow_def(upipe_fsrc, &uref));
    assert(uref != NULL);

    struct upipe_mgr *upipe_fsink_mgr = upipe_fsink_mgr_alloc();
    assert(upipe_fsink_mgr != NULL);
    struct upipe *upipe_fsink = upipe_flow_alloc(upipe_fsink_mgr,
            uprobe_pfx_adhoc_alloc(log, UPROBE_LOG_LEVEL, "file sink"), uref);
    assert(upipe_fsink != NULL);
    assert(upipe_set_upump_mgr(upipe_fsink, upump_mgr));
    if (delay) {
        assert(upipe_set_uclock(upipe_fsink, uclock));
        assert(upipe_sink_set_delay(upipe_fsink, delay));
    }
    assert(upipe_fsink_set_path(upipe_fsink, sink_file, mode));

    assert(upipe_set_output(upipe_fsrc, upipe_fsink));

    ev_loop(loop, 0);

    upipe_release(upipe_fsrc);
    upipe_mgr_release(upipe_fsrc_mgr); // nop

    upipe_release(upipe_fsink);
    upipe_mgr_release(upipe_fsink_mgr); // nop

    upump_mgr_release(upump_mgr);
    uref_mgr_release(uref_mgr);
    ubuf_mgr_release(ubuf_mgr);
    udict_mgr_release(udict_mgr);
    umem_mgr_release(umem_mgr);
    uclock_release(uclock);
    uprobe_log_free(log);
    uprobe_stdio_free(uprobe_stdio);

    ev_default_destroy();
    return 0;
}
