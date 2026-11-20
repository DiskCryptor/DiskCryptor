#ifndef _SHADOW_
#define _SHADOW_

#include "dcapi.h"

/*
 * Volume Shadow Copies vs. skip-unused (WP_SKIP_UNUSED). A shadow copy that exists when a
 * skip-unused session loads its allocation bitmap (the first step after a start, a mount or a
 * reboot) can still reference clusters the live file system has freed since; those are skipped,
 * so the shadow copy reads garbage afterwards. The GUI and dccon count the shadow copies of the
 * volume before a skip-unused start or resume and offer to delete them, as BitLocker does.
 *
 * w32_device: the volume GUID path as in vol_inf.w32_device ("\\?\Volume{...}", no trailing
 * backslash). dc_count_shadows also takes "\\?\GLOBALROOT\Device\..." (a volume without a GUID
 * name, see dc_next_volume); dc_delete_shadows does not (vssadmin needs the GUID path).
 */

/* the number of shadow copies of the volume (volsnap query, needs no VSS service) */
int dc_api dc_count_shadows(const wchar_t *w32_device, int *count);

/* deletes every shadow copy of the volume (vssadmin delete shadows /for= /all /quiet) and counts
   again: ST_OK when none is left, else ST_ERROR with *remaining the count left (-1 unknown).
   *abort (may be NULL) set or 10 minutes passed: vssadmin is ended, then counted. */
int dc_api dc_delete_shadows(const wchar_t *w32_device, int *remaining, volatile LONG *abort);

#endif
