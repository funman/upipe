/*
 * Copyright (C) 2016-2017 Open Broadcast Systems Ltd.
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
 *
 */

#undef NDEBUG
#include "upipe/uprobe.h"
#include "upipe/uprobe_stdio.h"
#include "upipe/uprobe_prefix.h"
#include "upipe/uprobe_uref_mgr.h"
#include "upipe/uprobe_upump_mgr.h"
#include "upipe/uprobe_uclock.h"
#include "upipe/uprobe_ubuf_mem.h"
#include "upipe/uprobe_dejitter.h"
#include "upipe/uclock.h"
#include "upipe/uclock_std.h"
#include "upipe/uref_clock.h"
#include "upipe/umem.h"
#include "upipe/umem_alloc.h"
#include "upipe/udict.h"
#include "upipe/udict_inline.h"
#include "upipe/uref.h"
#include "upipe/uref_std.h"
#include "upipe/upump.h"
#include "upump-ev/upump_ev.h"
#include "upipe/uuri.h"
#include "upipe/ustring.h"
#include "upipe/upipe.h"
#include "upipe-modules/upipe_udp_source.h"
#include "upipe-modules/upipe_udp_sink.h"
#include "upipe-modules/upipe_probe_uref.h"
#include "upipe-filters/upipe_rtp_feedback.h"
#include "upipe-modules/upipe_srt_handshake.h"

#include <arpa/inet.h>

#define UDICT_POOL_DEPTH 10
#define UREF_POOL_DEPTH 10
#define UBUF_POOL_DEPTH 10
#define UPUMP_POOL 10
#define UPUMP_BLOCKER_POOL 10
#define READ_SIZE 4096

static enum uprobe_log_level loglevel = UPROBE_LOG_DEBUG;

static struct upipe_mgr *udp_sink_mgr;
static struct upump_mgr *upump_mgr;

static struct upipe *upipe_udpsrc;
static struct upipe *upipe_udp_sink;

static int catch_udp(struct uprobe *uprobe, struct upipe *upipe,
                 int event, va_list args)
{
    if (event != UPROBE_UDPSRC_NEW_PEER)
        return uprobe_throw_next(uprobe, upipe, event, args);

    int sig = va_arg(args, int);
    if (sig != UPIPE_UDPSRC_SIGNATURE)
        return uprobe_throw_next(uprobe, upipe, event, args);

    const struct sockaddr *s = va_arg(args, struct sockaddr*);
    const socklen_t *len = va_arg(args, socklen_t *);

    char uri[INET6_ADDRSTRLEN+6];
    uint16_t port = 0;
    if (s->sa_family == AF_INET) {
        struct sockaddr_in *in = (struct sockaddr_in *)s;
        inet_ntop(AF_INET, &in->sin_addr, uri, sizeof(uri));
        port = ntohs(in->sin_port);
    } else {
        struct sockaddr_in6 *in6 = (struct sockaddr_in6 *)s;
        inet_ntop(AF_INET6, &in6->sin6_addr, uri, sizeof(uri));
        port = ntohs(in6->sin6_port);
    }

    size_t uri_len = strlen(uri);
    sprintf(&uri[uri_len], ":%hu", port);
    upipe_warn_va(upipe, "%s", uri);

    int udp_fd;
    ubase_assert(upipe_udpsrc_get_fd(upipe_udpsrc, &udp_fd));
    ubase_assert(upipe_udpsink_set_fd(upipe_udp_sink, dup(udp_fd)));

    ubase_assert(upipe_udpsink_set_peer(upipe_udp_sink, s, *len));

    return UBASE_ERR_NONE;
}

static void usage(const char *argv0) {
    fprintf(stdout, "Usage: %s [-d]  <udp source> <udp dest>", argv0);
    fprintf(stdout, "   -d: more verbose\n");
    fprintf(stdout, "   -q: more quiet\n");
    exit(EXIT_FAILURE);
}

static void stop(struct upump *upump)
{
    upump_stop(upump);
    upump_free(upump);

    upipe_release(upipe_udpsrc);
}

int main(int argc, char *argv[])
{
    char *dirpath, *srcpath;
    int opt;

    /* parse options */
    while ((opt = getopt(argc, argv, "qd")) != -1) {
        switch (opt) {
            case 'd':
                loglevel--;
                break;
            case 'q':
                loglevel++;
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

    /* setup environment */

    struct umem_mgr *umem_mgr = umem_alloc_mgr_alloc();
    struct udict_mgr *udict_mgr = udict_inline_mgr_alloc(UDICT_POOL_DEPTH,
                                                         umem_mgr, -1, -1);
    struct uref_mgr *uref_mgr = uref_std_mgr_alloc(UREF_POOL_DEPTH, udict_mgr,
                                                   0);
    upump_mgr = upump_ev_mgr_alloc_default(UPUMP_POOL,
                                                     UPUMP_BLOCKER_POOL);
    struct uprobe *logger = uprobe_stdio_alloc(NULL, stdout, loglevel);
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
    struct uclock *uclock = NULL;

    udp_sink_mgr = upipe_udpsink_mgr_alloc();

    uclock = uclock_std_alloc(UCLOCK_FLAG_REALTIME);

    logger = uprobe_uclock_alloc(logger, uclock);
    assert(logger != NULL);

    /* rtp source */
    struct uprobe uprobe_udp;
    uprobe_init(&uprobe_udp, catch_udp, uprobe_pfx_alloc(uprobe_use(logger),
                loglevel, "udp source"));

    struct upipe_mgr *upipe_udpsrc_mgr = upipe_udpsrc_mgr_alloc();
    upipe_udpsrc = upipe_void_alloc(upipe_udpsrc_mgr, &uprobe_udp);
    upipe_mgr_release(upipe_udpsrc_mgr);

    struct upipe_mgr *upipe_probe_uref_mgr = upipe_probe_uref_mgr_alloc();
    struct upipe *upipe_probe_uref = upipe_void_alloc_output(upipe_udpsrc,
            upipe_probe_uref_mgr, uprobe_use(logger));
    assert(upipe_probe_uref);
    upipe_mgr_release(upipe_probe_uref_mgr);
    upipe_release(upipe_probe_uref);

    struct upipe_mgr *upipe_srt_mgr = upipe_srt_mgr_alloc();
    struct upipe *upipe_srt = upipe_void_alloc_output(upipe_udpsrc,
            upipe_srt_mgr, uprobe_pfx_alloc(uprobe_use(logger), loglevel, "srt"));
    assert(upipe_srt);
    upipe_mgr_release(upipe_srt_mgr);

    struct upipe *upipe_srt_sub = upipe_void_alloc_sub(upipe_srt,
            uprobe_pfx_alloc(uprobe_use(logger), loglevel, "srt_sub"));
    assert(upipe_srt_sub);
    upipe_udp_sink = upipe_void_alloc_output(upipe_srt_sub,
            udp_sink_mgr, uprobe_pfx_alloc(uprobe_use(logger), loglevel,
                "data udpsink"));
    upipe_set_uri(upipe_udp_sink, dirpath);
    upipe_release(upipe_udp_sink);

    /* receive RTP */
    if (!ubase_check(upipe_set_uri(upipe_udpsrc, srcpath))) {
        return EXIT_FAILURE;
    }

    upipe_attach_uclock(upipe_udpsrc);
    upipe_udp_sink = upipe_void_chain_output(upipe_srt,
            udp_sink_mgr, uprobe_pfx_alloc(uprobe_use(logger), loglevel,
                "udpsink"));

    upipe_release(upipe_udp_sink);

    if (0) {
        struct upump *u = upump_alloc_timer(upump_mgr, stop, NULL, NULL,
                UCLOCK_FREQ, 0);
        upump_start(u);
    }

    /* fire loop ! */
    upump_mgr_run(upump_mgr, NULL);

    /* should never be here for the moment. todo: sighandler.
     * release everything */
    uprobe_clean(&uprobe_udp);
    uprobe_release(logger);

    upump_mgr_release(upump_mgr);
    uref_mgr_release(uref_mgr);
    udict_mgr_release(udict_mgr);
    umem_mgr_release(umem_mgr);
    uclock_release(uclock);
    upipe_mgr_release(udp_sink_mgr);

    return 0;
}
