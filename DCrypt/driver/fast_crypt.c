/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2007-2010 
    * ntldr <ntldr@diskcryptor.net> PGP key ID - 0xC48251EB4F8E4E6E
    *

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License version 3 as
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <ntifs.h>
#include "defines.h"
#include "misc.h"
#include "xts_fast.h"
#include "fast_crypt.h"

/* function types declaration */
KSTART_ROUTINE cp_worker_thread;

/* size the arrays by the KAFFINITY width, which bounds dc_cpu_count (it is counted
 * from KeQueryActiveProcessors); _WIN64 also covers ARM64. */
#if defined(_WIN64)
 #define MAX_CPU_COUNT 64
#else
 #define MAX_CPU_COUNT 32
#endif
C_ASSERT(MAX_CPU_COUNT >= sizeof(KAFFINITY) * 8);

/* CPU count used for the worker pool and the part split, clamped to the arrays
 * (never 0, it is a divisor) */
static ULONG cp_pool_cpu_count()
{
	ULONG n = dc_cpu_count;

	if (n == 0) n = 1;
	if (n > MAX_CPU_COUNT) n = MAX_CPU_COUNT;
	return n;
}

typedef struct _req_part {
	SLIST_ENTRY       entry;
	struct _req_item *item;
	u32               offset;
	u32               length;

} req_part;

typedef struct _req_item {
	int         is_encrypt;
	u32         length;
	const char *in;
	char       *out;
	u64         offset;
	fc_callback on_complete;
	void       *param;
	xts_key    *key;
	req_part    parts[MAX_CPU_COUNT];

} req_item;


static NPAGED_LOOKASIDE_LIST pool_req_mem;
static int                   pool_enabled;
static KEVENT                pool_signal_event;
static SLIST_HEADER          pool_head;
static HANDLE                pool_threads[MAX_CPU_COUNT];

static void cp_worker_thread(void *param)
{
	SLIST_ENTRY *entry;
	req_part    *part;
	req_item    *item;
	const char  *in;
	char        *out;
	u64          offset;
	u32          length;

	do
	{
		KeWaitForSingleObject(&pool_signal_event, Executive, KernelMode, FALSE, NULL);
		KeClearEvent(&pool_signal_event);
		
		while (entry = InterlockedPopEntrySList(&pool_head))
		{
			part = CONTAINING_RECORD(entry, req_part, entry);
			item = part->item;

			in     = item->in + part->offset;
			out    = item->out + part->offset;
			offset = item->offset + part->offset;
			length = part->length;

			if (item->is_encrypt != 0) {
				xts_encrypt(in, out, length, offset, item->key);
			} else {
				xts_decrypt(in, out, length, offset, item->key);
			}
			if (lock_xchg_add(&item->length, 0-length) == length) {
				item->on_complete(item->param);
				ExFreeToNPagedLookasideList(&pool_req_mem, item);
			}
		}	
	} while (pool_enabled != 0);

	PsTerminateSystemThread(STATUS_SUCCESS);
}

void cp_parallelized_crypt(
	   int   is_encrypt, xts_key *key, fc_callback on_complete, 
	   void *param, const unsigned char *in, unsigned char *out, u32 len, u64 offset)
{
	req_item *item;
	req_part *part;
	u32       part_sz;
	u32       part_of;
	ULONG     cpu_n, part_n;

	if ( (len < F_OP_THRESOLD) ||
		 ((item = ExAllocateFromNPagedLookasideList(&pool_req_mem)) == NULL) )
	{
		if (is_encrypt != 0) {
			xts_encrypt(in, out, len, offset, key);
		} else {
			xts_decrypt(in, out, len, offset, key);
		}
		on_complete(param); return;
	}
	item->is_encrypt = is_encrypt;
	item->length = len;
	item->in  = in;
	item->out = out;
	item->offset      = offset;
	item->on_complete = on_complete;
	item->param = param;
	item->key   = key;

	cpu_n   = cp_pool_cpu_count();
	part_sz = _align(len / cpu_n, F_MIN_REQ);
	part_of = 0; part = &item->parts[0]; part_n = 0;
	do
	{
		/* never more than cpu_n (<= MAX_CPU_COUNT) parts - the last one takes the
		 * remainder (only reachable for a len that is not a multiple of 512) */
		if (++part_n == cpu_n) part_sz = len;
		part_sz      = min(part_sz, len);
		part->item   = item;
		part->offset = part_of;
		part->length = part_sz;

		InterlockedPushEntrySList(&pool_head, &part->entry);

		part_of += part_sz; len -= part_sz; part++;
	} while (len != 0);

	KeSetEvent(&pool_signal_event, IO_NO_INCREMENT, FALSE);
}

static void cp_fast_complete(PKEVENT sync_event)
{
	KeSetEvent(sync_event, IO_NO_INCREMENT, FALSE);
}

void cp_fast_crypt_op(
		int   is_encrypt, xts_key *key,
		const unsigned char *in, unsigned char *out, u32 len, u64 offset)
{
	KEVENT sync_event;
	
	KeInitializeEvent(&sync_event, NotificationEvent, FALSE);

	cp_parallelized_crypt(is_encrypt, key, cp_fast_complete, &sync_event, in, out, len, offset);		
	KeWaitForSingleObject(&sync_event, Executive, KernelMode, FALSE, NULL);
}

void cp_free_fast_crypt()
{
	int i;

	/* disable thread pool */
	if (lock_xchg(&pool_enabled, 0) == 0) {
		return;
	}
	/* stop all threads */
	for (i = 0; i < MAX_CPU_COUNT; i++)
	{
		if (pool_threads[i] != NULL) {
			KeSetEvent(&pool_signal_event, IO_NO_INCREMENT, FALSE);
			ZwWaitForSingleObject(pool_threads[i], FALSE, NULL);
			ZwClose(pool_threads[i]);
		}
	}
	/* free memory */
	memset(&pool_threads, 0, sizeof(pool_threads));
	ExDeleteNPagedLookasideList(&pool_req_mem);
}

int cp_init_fast_crypt()
{
	ULONG i;

	/* enable thread pool */
	if (lock_xchg(&pool_enabled, 1) != 0) return ST_OK;
	/* initialize resources */
	ExInitializeNPagedLookasideList(&pool_req_mem, NULL, NULL, 0, sizeof(req_item), '3_cd', 0);
	KeInitializeEvent(&pool_signal_event, NotificationEvent, FALSE);	
	InitializeSListHead(&pool_head);

	/* start worker threads */
	for (i = 0; i < cp_pool_cpu_count(); i++)	/* bounded by pool_threads[] */
	{
		if (start_system_thread(cp_worker_thread, NULL, &pool_threads[i]) != ST_OK) {
			cp_free_fast_crypt(); return ST_ERR_THREAD;
		}
	}
	return ST_OK;
}