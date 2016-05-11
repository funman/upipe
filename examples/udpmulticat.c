/*
 * Copyright (C) 2012-2014 OpenHeadend S.A.R.L.
 *
 * Authors: Benjamin Cohen
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
 
[udp] -- data --> [dup] --> {start: front,0;} [datasink], [genaux]
[genaux] -- aux --> [auxsink]

+-----+  data   +-----+          +----------+  aux   +---------+
| udp | ------> | dup | -+-----> |  genaux  | -----> | auxsink |
+-----+         +-----+  |       +----------+        +---------+
                         |       +----------+
                         +-----> | datasink |
                                 +----------+
 */

/** @file
 * @short Upipe implementation of a multicat-like udp recorder/forwarder
 *
 * Pipes and uref/ubuf/upump managers definitions are hardcoded in this
 * example.
 *
 * Usage example :
 *   ./udpmulticat -d -r 270000000 @239.255.42.77:1234 foo/ .ts will
 * listen to multicast address 239.255.42.77:1234 and outputfiles in
 * folder foo (which needs to exist) the way multicat would do.
 * The rotate interval is 10sec (10sec at 27MHz gives 27000000).
 * Please pay attention to the trailing slash in "foo/".
 * If no suffix is specified, udpmulticat will send data to a udp socket.
 */

#undef NDEBUG

#include <upipe/uprobe.h>
#include <upipe/uprobe_stdio.h>
#include <upipe/uprobe_prefix.h>
#include <upipe/uprobe_uref_mgr.h>
#include <upipe/uprobe_upump_mgr.h>
#include <upipe/uprobe_uclock.h>
#include <upipe/uprobe_ubuf_mem.h>
#include <upipe/uprobe_dejitter.h>
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
#include <upipe-modules/upipe_genaux.h>
#include <upipe-modules/upipe_dup.h>
#include <upipe-modules/upipe_udp_source.h>
#include <upipe-modules/upipe_rtp_source.h>
#include <upipe-modules/upipe_file_source.h>
#include <upipe-modules/upipe_file_sink.h>
#include <upipe-modules/upipe_multicat_sink.h>
#include <upipe-modules/upipe_udp_sink.h>
#include <upipe-ts/upipe_ts_getpcr.h>
#include <upipe-ts/upipe_ts_pcr_interpolator.h>
#include <upipe-ts/upipe_ts_align.h>
#include <upipe-dveo/upipe_dveo_asi_sink.h>

#include <stdbool.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>
#include <signal.h>

#include <ev.h>

#define UDICT_POOL_DEPTH 10
#define UREF_POOL_DEPTH 10
#define UBUF_POOL_DEPTH 10
#define UPUMP_POOL 10
#define UPUMP_BLOCKER_POOL 10
#define READ_SIZE 4096
#define UPROBE_LOG_LEVEL UPROBE_LOG_WARNING

static void usage(const char *argv0) {
    fprintf(stdout, "Usage: %s [-d] [-r <rotate>] <udp source> <dest dir/prefix> [<suffix>]\n", argv0);
    fprintf(stdout, "   -d: force debug log level\n");
    fprintf(stdout, "   -r: rotate interval in 27MHz unit\n");
    fprintf(stdout, "If no <suffix> specified, udpmulticat sends data to a udp socket\n");
    exit(EXIT_FAILURE);
}

/** definition of our uprobe */
static int catch(struct uprobe *uprobe, struct upipe *upipe,
                 int event, va_list args)
{
    switch (event) {
        default:
            break;
        case UPROBE_SOURCE_END:
            upipe_release(upipe);
            break;
    }
    return UBASE_ERR_NONE;
}

int main(int argc, char *argv[])
{
    const char *srcpath, *dirpath, *suffix = NULL;
    bool udp = false;
    uint64_t rotate = 0;
    int opt;
    enum uprobe_log_level loglevel = UPROBE_LOG_LEVEL;

    /* parse options */
    while ((opt = getopt(argc, argv, "r:d")) != -1) {
        switch (opt) {
            case 'r':
                rotate = strtoull(optarg, NULL, 0);
                break;
            case 'd':
                loglevel = UPROBE_LOG_DEBUG;
                break;
            default:
                usage(argv[0]);
        }
    }
    if (argc - optind < 2) {
        usage(argv[0]);
    }
    srcpath = argv[optind++];
    dirpath = argv[optind++];
    if (argc - optind >= 1) {
        suffix = argv[optind++];
    } else {
        udp = true;
    }

    /* setup environnement */

    struct ev_loop *loop = ev_default_loop(0);
    struct umem_mgr *umem_mgr = umem_alloc_mgr_alloc();
    struct udict_mgr *udict_mgr = udict_inline_mgr_alloc(UDICT_POOL_DEPTH,
                                                         umem_mgr, -1, -1);
    struct uref_mgr *uref_mgr = uref_std_mgr_alloc(UREF_POOL_DEPTH, udict_mgr,
                                                   0);
    struct upump_mgr *upump_mgr = upump_ev_mgr_alloc(loop, UPUMP_POOL,
                                                     UPUMP_BLOCKER_POOL);
    struct uprobe uprobe;
    uprobe_init(&uprobe, catch, NULL);
    struct uprobe *logger = uprobe_stdio_alloc(&uprobe, stdout, loglevel);
    assert(logger != NULL);
    struct uprobe *uprobe_dejitter = uprobe_dejitter_alloc(logger, true, 0);
    assert(uprobe_dejitter != NULL);

    logger = uprobe_uref_mgr_alloc(uprobe_dejitter, uref_mgr);

    assert(logger != NULL);
    logger = uprobe_upump_mgr_alloc(logger, upump_mgr);
    assert(logger != NULL);
    logger = uprobe_ubuf_mem_alloc(logger, umem_mgr, UBUF_POOL_DEPTH,
                                   UBUF_POOL_DEPTH);
    assert(logger != NULL);
    struct uclock *uclock = NULL;//;
    struct upipe_mgr *asi_sink_mgr = upipe_dveo_asi_sink_mgr_alloc();

    struct upipe *upipe_asi_sink = upipe_void_alloc(asi_sink_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "asisink"));
    upipe_set_option(upipe_asi_sink, "card-idx", "0");

    if (!ubase_check(upipe_dveo_asi_sink_get_uclock(upipe_asi_sink, &uclock)))
        return EXIT_FAILURE;

    logger = uprobe_uclock_alloc(logger, uclock);
    assert(logger != NULL);
#if 1
    /* rtp source */
    struct upipe_mgr *upipe_rtpsrc_mgr = upipe_rtpsrc_mgr_alloc();
    struct upipe *upipe_rtpsrc = upipe_void_alloc(upipe_rtpsrc_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "rtp source"));

    upipe_mgr_release(upipe_rtpsrc_mgr);
    if (!ubase_check(upipe_set_uri(upipe_rtpsrc, srcpath))) {
        return EXIT_FAILURE;
    }
    upipe_attach_uclock(upipe_rtpsrc);
#else
    struct upipe_mgr *upipe_fsrc_mgr = upipe_fsrc_mgr_alloc();
    struct upipe *upipe_rtpsrc = upipe_void_alloc(upipe_fsrc_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "fsrc"));

    if (!ubase_check(upipe_set_uri(upipe_rtpsrc,
                    "file:///home/obe/media/opuslow-2014-11-10.ts"))) {
        return EXIT_FAILURE;
    }
    upipe_attach_uclock(upipe_rtpsrc);
#endif

    assert(udp);

    /* send to udp */

    struct upipe_mgr *ts_align_mgr = upipe_ts_align_mgr_alloc();
    struct upipe *upipe_ts_align = upipe_void_alloc_output(upipe_rtpsrc,
            ts_align_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "tsalign"));
    upipe_release(upipe_rtpsrc);

    struct upipe_mgr *ts_getpcr_mgr = upipe_ts_getpcr_mgr_alloc();
    struct upipe *upipe_ts_getpcr = upipe_void_alloc_output(upipe_ts_align,
            ts_getpcr_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "getpcr"));
    upipe_release(upipe_ts_align);
    struct upipe_mgr *ts_pcr_interpolator_mgr = upipe_ts_pcr_interpolator_mgr_alloc();
    struct upipe *upipe_ts_pcr_interpolator = upipe_void_alloc_output(upipe_ts_getpcr,
            ts_pcr_interpolator_mgr,
            uprobe_pfx_alloc(uprobe_use(logger),
                             loglevel, "pcr_interpolator"));
    upipe_release(upipe_ts_getpcr);
    upipe_set_output(upipe_ts_pcr_interpolator, upipe_asi_sink);
    upipe_release(upipe_ts_pcr_interpolator);
    upipe_release(upipe_asi_sink);

    /* fire loop ! */
    ev_loop(loop, 0);

    /* should never be here for the moment. todo: sighandler.
     * release everything */
    uprobe_release(logger);
    uprobe_clean(&uprobe);

    upump_mgr_release(upump_mgr);
    uref_mgr_release(uref_mgr);
    udict_mgr_release(udict_mgr);
    umem_mgr_release(umem_mgr);
    //uclock_release(uclock);

    ev_default_destroy();
    return 0;
}
