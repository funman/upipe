/*
 * Copyright (C) 2012-2015 OpenHeadend S.A.R.L.
 * Copyright (C) 2016 Open Broadcast Systems Ltd
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
 * @short Upipe sink module for DVEO ASI cards
 */

#include <upipe/ubase.h>
#include <upipe/ulist.h>
#include <upipe/uprobe.h>
#include <upipe/uclock.h>
#include <upipe/uref.h>
#include <upipe/uref_block.h>
#include <upipe/uref_clock.h>
#include <upipe/upump.h>
#include <upipe/upump_blocker.h>
#include <upipe/ubuf.h>
#include <upipe/upipe.h>
#include <upipe/upipe_helper_upipe.h>
#include <upipe/upipe_helper_urefcount.h>
#include <upipe/upipe_helper_void.h>
#include <upipe/upipe_helper_upump_mgr.h>
#include <upipe/upipe_helper_upump.h>
#include <upipe/upipe_helper_input.h>
#include <upipe/upipe_helper_uclock.h>
#include <upipe-dveo/upipe_dveo_asi_sink.h>

#include <sys/ioctl.h>
#include "asi_ioctl.h"

#include <stdlib.h>
#include <termios.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/poll.h>

/** @hidden */
static bool upipe_dveo_asi_sink_output(struct upipe *upipe, struct uref *uref,
                               struct upump **upump_p);

struct uclock_dveo_asi_sink {
    struct urefcount urefcount;
    struct uclock uclock;
    unsigned int last_val;
    uint64_t wraparounds;
};

/** @internal @This is the private context of a file sink pipe. */
struct upipe_dveo_asi_sink {
    /** refcount management structure */
    struct urefcount urefcount;

    /** upump manager */
    struct upump_mgr *upump_mgr;
    /** write watcher */
    struct upump *upump;
    /** sync watcher */
    struct upump *upump_sync;

    /** delay applied to system clock ref when uclock is provided */
    uint64_t latency;
    /** file descriptor */
    int fd;

    /** card index */
    int card_idx;

    /** temporary uref storage */
    struct uchain urefs;
    /** nb urefs in storage */
    unsigned int nb_urefs;
    /** max urefs in storage */
    unsigned int max_urefs;
    /** list of blockers */
    struct uchain blockers;

    /** hardware clock */
    struct uclock_dveo_asi_sink uclock;

    /** first timestamp */
    bool first_timestamp;

    /** last PCR */
    uint64_t last_cr;

    /** public upipe structure */
    struct upipe upipe;
};

UPIPE_HELPER_UPIPE(upipe_dveo_asi_sink, upipe, UPIPE_DVEO_ASI_SINK_SIGNATURE)
UPIPE_HELPER_UREFCOUNT(upipe_dveo_asi_sink, urefcount, upipe_dveo_asi_sink_free)
UPIPE_HELPER_VOID(upipe_dveo_asi_sink)
UPIPE_HELPER_UPUMP_MGR(upipe_dveo_asi_sink, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_dveo_asi_sink, upump, upump_mgr)
UPIPE_HELPER_UPUMP(upipe_dveo_asi_sink, upump_sync, upump_mgr)
UPIPE_HELPER_INPUT(upipe_dveo_asi_sink, urefs, nb_urefs, max_urefs, blockers, upipe_dveo_asi_sink_output)
UBASE_FROM_TO(uclock_dveo_asi_sink, uclock, uclock, uclock)
UBASE_FROM_TO(uclock_dveo_asi_sink, urefcount, urefcount, urefcount)
UBASE_FROM_TO(upipe_dveo_asi_sink, uclock_dveo_asi_sink, uclock_dveo_asi_sink, uclock)

/** @internal @This is called when the file descriptor can be written again.
 * Unblock the sink and unqueue all queued buffers.
 *
 * @param upump description structure of the watcher
 */
static void upipe_dveo_asi_sink_watcher(struct upump *upump)
{
    struct upipe *upipe = upump_get_opaque(upump, struct upipe *);
    upipe_dveo_asi_sink_set_upump(upipe, NULL);
    upipe_dveo_asi_sink_output_input(upipe);
    upipe_dveo_asi_sink_unblock_input(upipe);
    if (upipe_dveo_asi_sink_check_input(upipe)) {
        /* All packets have been output, release again the pipe that has been
         * used in @ref upipe_dveo_asi_sink_input. */
        upipe_release(upipe);
    }
}

/** @This starts the watcher waiting for the sink to unblock.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_dveo_asi_sink_poll(struct upipe *upipe)
{
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    if (unlikely(!ubase_check(upipe_dveo_asi_sink_check_upump_mgr(upipe)))) {
        upipe_err_va(upipe, "can't get upump_mgr");
        upipe_throw_fatal(upipe, UBASE_ERR_UPUMP);
        return;
    }
    struct upump *watcher = upump_alloc_fd_write(upipe_dveo_asi_sink->upump_mgr,
            upipe_dveo_asi_sink_watcher, upipe, upipe->refcount, upipe_dveo_asi_sink->fd);
    if (unlikely(watcher == NULL)) {
        upipe_err(upipe, "can't create watcher");
        upipe_throw_fatal(upipe, UBASE_ERR_UPUMP);
    } else {
        upipe_dveo_asi_sink_set_upump(upipe, watcher);
        upump_start(watcher);
    }
}


static uint64_t uclock_dveo_asi_sink_now(struct uclock *uclock)
{
    struct uclock_dveo_asi_sink *uclock_dveo_asi_sink = uclock_dveo_asi_sink_from_uclock(uclock);
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_uclock_dveo_asi_sink(uclock_dveo_asi_sink);

    if (upipe_dveo_asi_sink->fd < 0)
        return 0;

    unsigned int val;
    struct upipe *upipe = &upipe_dveo_asi_sink->upipe;
    if (ioctl(upipe_dveo_asi_sink->fd, ASI_IOC_TXGET27COUNT, &val) < 0) {
        upipe_err_va(upipe, "can't get hardware clock (%m)");
        return 0;
    }

    if (val < uclock_dveo_asi_sink->last_val) {
        upipe_notice(upipe, "clock wrapping");
        uclock_dveo_asi_sink->wraparounds++;
    }

    uclock_dveo_asi_sink->last_val = val;

    return (uclock_dveo_asi_sink->wraparounds << 32) + val;
}

/** @This frees a uclock.
 *
 * @param urefcount pointer to urefcount
 */
static void uclock_dveo_asi_sink_free(struct urefcount *urefcount)
{
    struct uclock_dveo_asi_sink *uclock_dveo_asi_sink = uclock_dveo_asi_sink_from_urefcount(urefcount);

    urefcount_clean(urefcount);
    uclock_dveo_asi_sink->uclock.uclock_now = NULL;
}

static void uclock_dveo_asi_sink_init(struct uclock_dveo_asi_sink *uclock_dveo_asi_sink)
{
    urefcount_init(uclock_dveo_asi_sink_to_urefcount(uclock_dveo_asi_sink), uclock_dveo_asi_sink_free);
    uclock_dveo_asi_sink->uclock.refcount = uclock_dveo_asi_sink_to_urefcount(uclock_dveo_asi_sink);
    uclock_dveo_asi_sink->uclock.uclock_now = uclock_dveo_asi_sink_now;
    uclock_dveo_asi_sink->last_val = 0;
    uclock_dveo_asi_sink->wraparounds = 0;
}


/** @internal @This allocates a file sink pipe.
 *
 * @param mgr common management structure
 * @param uprobe structure used to raise events
 * @param signature signature of the pipe allocator
 * @param args optional arguments
 * @return pointer to upipe or NULL in case of allocation error
 */
static struct upipe *upipe_dveo_asi_sink_alloc(struct upipe_mgr *mgr,
                                       struct uprobe *uprobe,
                                       uint32_t signature, va_list args)
{
    struct upipe *upipe = upipe_dveo_asi_sink_alloc_void(mgr, uprobe, signature, args);
    if (unlikely(upipe == NULL))
        return NULL;

    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    upipe_dveo_asi_sink_init_urefcount(upipe);
    upipe_dveo_asi_sink_init_upump_mgr(upipe);
    upipe_dveo_asi_sink_init_upump(upipe);
    upipe_dveo_asi_sink_init_input(upipe);
    upipe_dveo_asi_sink->latency = 0;
    upipe_dveo_asi_sink->fd = -1;
    upipe_dveo_asi_sink->card_idx = 0;
    upipe_dveo_asi_sink->last_cr = 0;
    upipe_dveo_asi_sink->first_timestamp = true;
    upipe_throw_ready(upipe);
    return upipe;
}

/** @internal @This outputs data to the file sink.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 * @return true if the uref was processed
 */
static bool upipe_dveo_asi_sink_output(struct upipe *upipe, struct uref *uref,
                               struct upump **upump_p)
{
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    const char *def;
    if (unlikely(ubase_check(uref_flow_get_def(uref, &def)))) {
        uint64_t latency = 0;
        uref_clock_get_latency(uref, &latency);

        // TODO
        //upipe_warn_va(upipe, "def %s - latency %"PRIu64" stored latency %"PRIu64,
        //    def, latency, upipe_dveo_asi_sink->latency);

        if (latency > upipe_dveo_asi_sink->latency)
            upipe_dveo_asi_sink->latency = latency;
        uref_free(uref);
        return true;
    }

    int fd = upipe_dveo_asi_sink->fd;

    if (unlikely(fd == -1)) {
        upipe_warn(upipe, "received a buffer before opening the device");
        uref_free(uref);
        return true;
    }

    uint64_t cr_sys = 0;
    uint64_t cr_prog = 0;
    uint64_t cr_orig = 0;

    uref_clock_get_cr_prog(uref, &cr_prog);
    uref_clock_get_cr_orig(uref, &cr_orig);

    if (unlikely(!ubase_check(uref_clock_get_cr_sys(uref, &cr_sys)))) {
        upipe_warn(upipe, "received non-dated buffer");
        uref_free(uref);
        return true;
    }

    if (cr_prog && cr_prog != -1) {
        upipe_dveo_asi_sink->last_cr = cr_prog;
    } else {
        int type;
        uref_clock_get_date_prog(uref, &cr_prog, &type);
        struct urational rate = {0, 0};
        uref_clock_get_rate(uref, &rate);
        if (!rate.num || !rate.den)
            rate.num = rate.den = 1;
        cr_prog = upipe_dveo_asi_sink->last_cr +
            (cr_prog - upipe_dveo_asi_sink->last_cr) * rate.num / rate.den;
    }

    if (!cr_prog || cr_prog == -1) {
        upipe_warn(upipe, "prog not set, not writing anything");
        uref_free(uref);
        return true;
    }

    cr_prog += upipe_dveo_asi_sink->latency;

    uint64_t hdr_size;
    if (!ubase_check(uref_block_get_header_size(uref, &hdr_size)))
        hdr_size = 0;

    bool discontinuity = ubase_check(uref_flow_get_discontinuity(uref));
    if (discontinuity) {
        upipe_warn_va(upipe, "DISCONTINUITY, resetting timestamp");
        upipe_dveo_asi_sink->first_timestamp = true;
            //fsync (fd); // NOT GOOD, BLOCKING
    }

    bool reset_first_timestamp = false;

    if (hdr_size == 0) {
        /* alloc header */
        struct ubuf *header = ubuf_block_alloc(uref->ubuf->mgr, 8);
        if (unlikely(!header)) {
            uref_free(uref);
            return false;
        }

        /* Use cr_sys as 63-bits timestamp */
        union {
            uint8_t timestamp[8];
            uint64_t pcr;
        } timestamp;

        timestamp.pcr = cr_prog;
        if (upipe_dveo_asi_sink->first_timestamp) {
            upipe_dveo_asi_sink->first_timestamp = false;
            timestamp.pcr |= 1LLU << 63; /* Set MSB = Set the counter */
            timestamp.pcr -= 270000; /* add 10ms latency */
            reset_first_timestamp = true; /* Make sure we set the counter */
        }

        /* write header */
        int size = 8;
        uint8_t *header_write_ptr;
        if (!ubase_check(ubuf_block_write(header, 0, &size, &header_write_ptr))) {
            upipe_err(upipe, "could not write header");
            ubuf_free(header);
            uref_free(uref);
            return true;
        }
        memcpy(header_write_ptr, timestamp.timestamp, 8);
        uref_block_unmap(uref, 0);

        /* append payload (current ubuf) to header to form segmented ubuf */
        struct ubuf *payload = uref_detach_ubuf(uref);
        if (unlikely(!ubase_check(ubuf_block_append(header, payload)))) {
            upipe_warn(upipe, "could not append payload to header");
            ubuf_free(header);
            ubuf_free(payload);
            uref_free(uref);
            return true;
        }
        uref_attach_ubuf(uref, header);
        uref_block_set_header_size(uref, 8);

        upipe_dbg_va(upipe, "received dated buffer: PROG %"PRId64" ORIG %"PRId64
                " SYS %"PRId64" TIMESTAMP %"PRIu64,
                cr_prog, cr_orig, cr_sys, timestamp.pcr);
    }

    for (;;) {
        int iovec_count = uref_block_iovec_count(uref, 0, -1);
        if (unlikely(iovec_count == -1)) {
            upipe_warn(upipe, "cannot read ubuf buffer");
            break;
        }
        if (unlikely(iovec_count == 0)) {
            break;
        }

        struct iovec iovecs[iovec_count];
        if (unlikely(!ubase_check(uref_block_iovec_read(uref, 0, -1,
                                                        iovecs)))) {
            upipe_warn(upipe, "cannot read ubuf buffer");
            break;
        }

        ssize_t ret = writev(upipe_dveo_asi_sink->fd, iovecs, iovec_count);
        uref_block_iovec_unmap(uref, 0, -1, iovecs);

        if (unlikely(ret == -1)) {
            switch (errno) {
                case EINTR:
                    continue;
                case EAGAIN:
#if EAGAIN != EWOULDBLOCK
                case EWOULDBLOCK:
#endif
                    upipe_notice_va(upipe, "polling");
                    upipe_dveo_asi_sink_poll(upipe);
                    return false;
                default:
                    break;
            }
            upipe_warn_va(upipe, "write error to device %d (%m)", upipe_dveo_asi_sink->card_idx);
            upipe_dveo_asi_sink_set_upump(upipe, NULL);
            upipe_throw_sink_end(upipe);
            break;
        }

        size_t uref_size;
        if (ubase_check(uref_block_size(uref, &uref_size)) &&
            uref_size == ret) {
            reset_first_timestamp = false;
            break;
        }
        uref_block_resize(uref, ret, -1);
    }

    uref_free(uref);

    if (reset_first_timestamp)
        upipe_dveo_asi_sink->first_timestamp = true;

    static uint64_t sum;
    sum += 188;
    //upipe_notice_va(upipe, "Wrote %"PRIu64" bytes into the card", sum);

    int val;

    if (ioctl(fd, ASI_IOC_TXGETEVENTS, &val) < 0)
        upipe_err_va(upipe, "ioctl TXGETEVENTS failed (%m)");
    else {
        if (val & ASI_EVENT_TX_BUFFER)
            upipe_notice(upipe, "driver transmit buffer queue underrun");
        if (val & ASI_EVENT_TX_FIFO)
            upipe_notice(upipe, "onboard transmit FIFO underrun");
        if (val & ASI_EVENT_TX_DATA) {
            upipe_notice(upipe, "transmit data status change");
            if (ioctl(fd, ASI_IOC_TXGETTXD, &val) < 0)
                upipe_err_va(upipe, "ioctl TXGETTXDfailed (%m)");
            else
                upipe_notice_va(upipe, "transmitting: %d", val);
        }
    }

    if (ioctl(fd, ASI_IOC_TXGETBUFLEVEL, &val) < 0)
        upipe_err_va(upipe, "ioctl TXGETBUFLEVEL failed (%m)");
    else {
        static int old;
#define MARGIN 1
        if ((val - MARGIN) >  old || (val + MARGIN) < old) {
            float secs = (float)val * 6 * 196 * 8 / 10500000;
            upipe_notice_va(upipe, "buf level %d -> %.2fs", val, secs);
            old = val;
        }
    }

    if (ioctl(fd, ASI_IOC_TXGETBYTECOUNT, &val) < 0)
        upipe_err_va(upipe, "ioctl TXGETBYTECOUNTfailed (%m)");
    else {
        /*static uint64_t byte_sum;
        byte_sum += val;
        upipe_notice_va(upipe, "byte count %d -> %"PRIu64, val, byte_sum);*/
    }

    return true;
}

/** @internal @This receives data.
 *
 * @param upipe description structure of the pipe
 * @param uref uref structure
 * @param upump_p reference to pump that generated the buffer
 */
static void upipe_dveo_asi_sink_input(struct upipe *upipe, struct uref *uref,
                              struct upump **upump_p)
{
    if (!upipe_dveo_asi_sink_check_input(upipe)) {
        upipe_dveo_asi_sink_hold_input(upipe, uref);
        upipe_dveo_asi_sink_block_input(upipe, upump_p);
    } else if (!upipe_dveo_asi_sink_output(upipe, uref, upump_p)) {
        upipe_dveo_asi_sink_hold_input(upipe, uref);
        upipe_dveo_asi_sink_block_input(upipe, upump_p);
        /* Increment upipe refcount to avoid disappearing before all packets
         * have been sent. */
        upipe_use(upipe);
    }
}

/** @internal @This sets the input flow definition.
 *
 * @param upipe description structure of the pipe
 * @param flow_def flow definition packet
 * @return an error code
 */
static int upipe_dveo_asi_sink_set_flow_def(struct upipe *upipe, struct uref *flow_def)
{
    if (flow_def == NULL)
        return UBASE_ERR_INVALID;
    UBASE_RETURN(uref_flow_match_def(flow_def, "block.mpegts."))
    flow_def = uref_dup(flow_def);
    UBASE_ALLOC_RETURN(flow_def)
    upipe_input(upipe, flow_def, NULL);
    return UBASE_ERR_NONE;
}

static void upipe_dveo_asi_sink_close(struct upipe *upipe)
{
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);

    if (unlikely(upipe_dveo_asi_sink->fd != -1)) {
        upipe_notice_va(upipe, "closing card %i", upipe_dveo_asi_sink->card_idx);
        ubase_clean_fd(&upipe_dveo_asi_sink->fd);
    }
    upipe_dveo_asi_sink_set_upump(upipe, NULL);
}

/* From the example code */
static ssize_t util_read(const char *name, char *buf, size_t count)
{
    ssize_t fd, ret;

    if ((fd = open (name, O_RDONLY)) < 0) {
        return fd;
    }
    ret = read (fd, buf, count);
    close (fd);
    return ret;
}

static ssize_t util_write(const char *name, const char *buf, size_t count)
{
    ssize_t fd, ret;

    if ((fd = open (name, O_WRONLY)) < 0) {
        return fd;
    }
    ret = write (fd, buf, count);
    close (fd);
    return ret;
}

static ssize_t
util_strtoul (const char *name, unsigned long int *val)
{
    ssize_t ret;
    char data[256], *endptr;
    unsigned long int tmp;

    memset (data, 0, sizeof (data));
    if ((ret = util_read (name, data, sizeof (data))) < 0) {
        return ret;
    }
    tmp = strtoul (data, &endptr, 0);
    if (*endptr != '\n') {
        return -1;
    }
    *val = tmp;
    return ret;
}

/** @internal @This asks to open the given device.
 *
 * @param upipe description structure of the pipe
 * @param path relative or absolute path of the file
 * @return an error code
 */
static int upipe_dveo_asi_sink_open(struct upipe *upipe)
{
#define BYPASS_MODE 1

    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    char path[20], sys[50], buf[20];

    static const char dev_fmt[] = "/dev/asitx%u";
    static const char sys_fmt[] = "/sys/class/asi/asitx%u/%s";
    static const char dvbm_sys_fmt[] = "/sys/class/dvbm/%u/%s";

    snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "timestamps");
    snprintf(buf, sizeof(buf), "%u\n", 2);
    if (util_write(sys, buf, sizeof(buf)) < 0) {
        upipe_err_va(upipe, "Couldn't set timestamp mode (%m)");
        return UBASE_ERR_EXTERNAL;
    }

    snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "bufsize");
    snprintf(buf, sizeof(buf), "%u\n", 6*(188+8)); /* minimum is 1024 */
    if (util_write(sys, buf, sizeof(buf)) < 0) {
        upipe_err_va(upipe, "Couldn't set buffer size (%m)");
        return UBASE_ERR_EXTERNAL;
    }

    snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "buffers");
    snprintf(buf, sizeof(buf), "%u\n", 10);
    if (util_write(sys, buf, sizeof(buf)) < 0) {
        upipe_err_va(upipe, "Couldn't set # of buffers (%m)");
        return UBASE_ERR_EXTERNAL;
    }

    snprintf(path, sizeof(path), dev_fmt, upipe_dveo_asi_sink->card_idx);
    int fd = open(path, O_WRONLY | O_NONBLOCK | O_CLOEXEC);
    if (unlikely(fd < 0)) {
        upipe_err_va(upipe, "can't open file %s (%m)", path);
        return UBASE_ERR_EXTERNAL;
    }

    snprintf(sys, sizeof(sys), dvbm_sys_fmt, upipe_dveo_asi_sink->card_idx, "bypass_mode");
    snprintf(buf, sizeof(buf), "%u", BYPASS_MODE);
    util_write(sys, buf, sizeof(buf)); /* Not all cards have this so don't fail */

    unsigned int cap;
    if (ioctl(fd, ASI_IOC_TXGETCAP, &cap) < 0) {
        upipe_err_va(upipe, "can't get tx caps (%m)");
        goto error;
    }

    unsigned long int bufsize;
    snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "bufsize");
    if (util_strtoul(sys, &bufsize) < 0) {
        upipe_err(upipe, "Couldn't read buffer size");
        goto error;
    }

    unsigned long int mode;
    snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "mode");
    if (util_strtoul(sys, &mode) < 0) {
        upipe_err(upipe, "Couldn't read buffer size");
        goto error;
    }

    unsigned int packetsize;
    switch (mode) {
        case ASI_CTL_TX_MODE_188:     packetsize = 188; break;
        case ASI_CTL_TX_MODE_MAKE204:
            upipe_dbg(upipe, "Appending 0x00 bytes to make 204 bytes packets");
        case ASI_CTL_TX_MODE_204:     packetsize = 204; break;
        default:
            upipe_err_va(upipe, "Unknown TX mode %d", mode);
            goto error;
    }

    unsigned long int clock_source = 0;
    if (cap & ASI_CAP_TX_SETCLKSRC) {
        snprintf(sys, sizeof(sys), sys_fmt, upipe_dveo_asi_sink->card_idx, "clock_source");
        if (util_strtoul(sys, &clock_source) < 0) {
            upipe_err(upipe, "Couldn't read clock source");
            goto error;
        }
    }

    switch (clock_source) {
        case ASI_CTL_TX_CLKSRC_ONBOARD:
            upipe_dbg(upipe, "Using onboard oscillator");
            break;
        case ASI_CTL_TX_CLKSRC_EXT:
            upipe_dbg(upipe, "Using external reference clock");
            break;
        case ASI_CTL_TX_CLKSRC_RX:
            upipe_dbg(upipe, "Using recovered receive clock");
            break;
        default:
            upipe_dbg(upipe, "Unknown clock source");
                break;
    }

    if (!(cap & ASI_CAP_TX_TIMESTAMPS)) {
        upipe_err(upipe, "Device does not support timestamps");
        goto error;
    }

    upipe_dveo_asi_sink->fd = fd;

    uclock_dveo_asi_sink_init(&upipe_dveo_asi_sink->uclock);
    urefcount_use(uclock_dveo_asi_sink_to_urefcount(&upipe_dveo_asi_sink->uclock));

    upipe_notice_va(upipe, "opening file %s", path);
    return UBASE_ERR_NONE;

error:
    close(fd);
    return UBASE_ERR_EXTERNAL;
}

/** @internal @This sets the content of a dveo_asi_sink option.
 *
 * @param upipe description structure of the pipe
 * @param option name of the option
 * @param content content of the option, or NULL to delete it
 * @return an error code
 */
static int upipe_dveo_asi_sink_set_option(struct upipe *upipe,
                                   const char *k, const char *v)
{
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    assert(k != NULL);

    if (unlikely(upipe_dveo_asi_sink->fd != -1))
        upipe_dveo_asi_sink_close(upipe);

    if (!strcmp(k, "card-idx"))
        upipe_dveo_asi_sink->card_idx = atoi(v);

    upipe_dveo_asi_sink_open(upipe);

    return UBASE_ERR_NONE;
}

/** @internal @This processes control commands on a file sink pipe.
 *
 * @param upipe description structure of the pipe
 * @param command type of command to process
 * @param args arguments of the command
 * @return an error code
 */
static int upipe_dveo_asi_sink_control(struct upipe *upipe, int command, va_list args)
{
    switch (command) {
        case UPIPE_ATTACH_UPUMP_MGR:
            upipe_dveo_asi_sink_set_upump(upipe, NULL);
            return upipe_dveo_asi_sink_attach_upump_mgr(upipe);
#if 0
        case UPIPE_ATTACH_UCLOCK:
            upipe_dveo_asi_sink_set_upump(upipe, NULL);
            //upipe_dveo_asi_sink_require_uclock(upipe);
            return UBASE_ERR_NONE;
#endif
        case UPIPE_DVEO_ASI_SINK_GET_UCLOCK: {
            UBASE_SIGNATURE_CHECK(args, UPIPE_DVEO_ASI_SINK_SIGNATURE)
                struct uclock **pp_uclock = va_arg(args, struct uclock **);
            struct upipe_dveo_asi_sink *dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
            struct uclock_dveo_asi_sink *uclock_dveo_asi_sink = upipe_dveo_asi_sink_to_uclock_dveo_asi_sink(dveo_asi_sink);
            struct uclock *uclock = uclock_dveo_asi_sink_to_uclock(uclock_dveo_asi_sink);
            *pp_uclock = uclock;
            return UBASE_ERR_NONE;
        }
        case UPIPE_REGISTER_REQUEST: {
            struct urequest *request = va_arg(args, struct urequest *);
            return upipe_throw_provide_request(upipe, request);
        }
        case UPIPE_UNREGISTER_REQUEST:
            return UBASE_ERR_NONE;
        case UPIPE_SET_FLOW_DEF: {
            struct uref *flow_def = va_arg(args, struct uref *);
            return upipe_dveo_asi_sink_set_flow_def(upipe, flow_def);
        }
        case UPIPE_SET_OPTION: {
            const char *k = va_arg(args, const char *);
            const char *v = va_arg(args, const char *);
            return upipe_dveo_asi_sink_set_option(upipe, k, v);

        }
        default:
            return UBASE_ERR_UNHANDLED;
    }
}

/** @This frees a upipe.
 *
 * @param upipe description structure of the pipe
 */
static void upipe_dveo_asi_sink_free(struct upipe *upipe)
{
    struct upipe_dveo_asi_sink *upipe_dveo_asi_sink = upipe_dveo_asi_sink_from_upipe(upipe);
    struct uclock_dveo_asi_sink *uclock_dveo_asi_sink = &upipe_dveo_asi_sink->uclock;

    urefcount_release(uclock_dveo_asi_sink_to_urefcount(uclock_dveo_asi_sink));

    if (likely(upipe_dveo_asi_sink->fd != -1)) {
        if (likely(upipe_dveo_asi_sink->fd > 0))
            upipe_notice_va(upipe, "closing device %d", upipe_dveo_asi_sink->card_idx);
        close(upipe_dveo_asi_sink->fd);
    }
    upipe_throw_dead(upipe);

    upipe_dveo_asi_sink_clean_upump(upipe);
    upipe_dveo_asi_sink_clean_upump_mgr(upipe);
    upipe_dveo_asi_sink_clean_input(upipe);
    upipe_dveo_asi_sink_clean_urefcount(upipe);
    upipe_dveo_asi_sink_free_void(upipe);
}

/** module manager static descriptor */
static struct upipe_mgr upipe_dveo_asi_sink_mgr = {
    .refcount = NULL,
    .signature = UPIPE_DVEO_ASI_SINK_SIGNATURE,

    .upipe_alloc = upipe_dveo_asi_sink_alloc,
    .upipe_input = upipe_dveo_asi_sink_input,
    .upipe_control = upipe_dveo_asi_sink_control,

    .upipe_mgr_control = NULL
};

/** @This returns the management structure for all file sink pipes.
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_dveo_asi_sink_mgr_alloc(void)
{
    return &upipe_dveo_asi_sink_mgr;
}
