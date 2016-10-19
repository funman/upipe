/** @file
 * @short Upipe netmap_enc module
 */

#ifndef _UPIPE_MODULES_UPIPE_NETMAP_SINK_H_
/** @hidden */
#define _UPIPE_MODULES_UPIPE_NETMAP_SINK_H_
#ifdef __cplusplus
extern "C" {
#endif

#include <upipe/upipe.h>

#define UPIPE_NETMAP_SINK_SIGNATURE UBASE_FOURCC('n','t','m','k')
/** @This returns the management structure for netmap_sink pipes.
 *
 * @return pointer to manager
 */
struct upipe_mgr *upipe_netmap_sink_mgr_alloc(void);

#ifdef __cplusplus
}
#endif
#endif
