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

#include <windows.h>

#include "main.h"
#include "threads.h"

#include "dlg_menu.h"

/*
   the act of the calling worker thread, NULL when this worker was superseded (a pause +
   resume or stop + start started another worker while this one waited outside crit_sect;
   the act may even be freed already). A superseded worker exits without touching the act.
   Called with crit_sect held. Does not prune the act list, unlike _create_act_thread.
*/
static
_dact *_current_act(
		const wchar_t *device
	)
{
	LONG        self = (LONG)GetCurrentThreadId( );
	list_entry *item;

	for (
		item = __action.flink;
		item != &__action;
		item = item->flink
		)
	{
		_dact *act = contain_record(item, _dact, list);
		if ( !wcscmp(act->device, device) )
		{
			return ( act->worker_id == self ) ? act : NULL;
		}
	}
	return NULL;
}


/* the device's act whichever worker drives it (bad block count); call in crit_sect */
static
_dact *_device_act(
		const wchar_t *device
	)
{
	list_entry *item;

	for (
		item = __action.flink;
		item != &__action;
		item = item->flink
		)
	{
		_dact *act = contain_record(item, _dact, list);
		if ( !wcscmp(act->device, device) )
		{
			return act;
		}
	}
	return NULL;
}


static
DWORD WINAPI _bad_blocks_msg_proc(
		LPVOID lparam
	)
{
	MessageBox( HWND_DESKTOP, (wchar_t*)lparam, L"Warning", MB_OK | MB_ICONWARNING );
	free( lparam );
	return 0;
}


/*
   tell the user that blocks with bad sectors were passed. Shown from its own thread:
   the worker must exit - a new operation on the volume waits for it (_worker_begin) and
   _clear_act_list keeps its act until then.
*/
#define BAD_BLOCKS_FINISHED 0
#define BAD_BLOCKS_ERROR    1
#define BAD_BLOCKS_STOPPED  2

static
void _show_bad_blocks(
		const wchar_t *device,
		int            act_type,
		int            bad_blocks,
		int            why  /* BAD_BLOCKS_* */
	)
{
	const size_t msg_len = 1024;
	dc_status    st;
	wchar_t     *msg;
	wchar_t     *act_name;
	HANDLE       h_thread;

	switch ( act_type )
	{
		case ACT_ENCRYPT:   act_name = L"Encryption";   break;
		case ACT_DECRYPT:   act_name = L"Decryption";   break;
		case ACT_REENCRYPT: act_name = L"Reencryption"; break;
		default:            act_name = L"Operation";    break;
	}
	if ( dc_get_device_status( (wchar_t*)device, &st ) != ST_OK )
	{
		st.mnt_point[0] = 0;
	}
	if ( (msg = malloc(msg_len * sizeof(wchar_t))) == NULL )
	{
		return;
	}
	_snwprintf(
		msg, msg_len - 1,
		L"%s of volume [%s] %s, and %d block(s) contained sectors that could not "
		L"be read or written (bad sectors).\n\n"
		L"The contents of these sectors are lost: unreadable sectors now read as zeros. "
		L"Check the disk for errors and restore the affected files from a backup.",
		act_name, st.mnt_point[0] ? st.mnt_point : device,
		why == BAD_BLOCKS_ERROR ? L"stopped with an error" :
		why == BAD_BLOCKS_STOPPED ? L"was stopped" : L"finished", bad_blocks
		);
	msg[msg_len - 1] = 0;

	if ( (h_thread = CreateThread(NULL, 0, _bad_blocks_msg_proc, msg, 0, NULL)) != NULL )
	{
		CloseHandle( h_thread );
	} else
	{
		_bad_blocks_msg_proc( msg );
	}
}


/*
   start parameter of a worker: its node and the handle of the worker it supersedes (NULL if
   none). A new worker waits for the superseded one to exit before its first step: that one
   may still be inside a step, and the driver refuses a second concurrent step with an error.
*/
typedef struct _worker_ctx {
	_dnode *node;
	HANDLE  h_prev;

} _worker_ctx;

static
_dnode *_worker_begin(
		LPVOID lparam
	)
{
	_worker_ctx *ctx    = (_worker_ctx *)lparam;
	_dnode      *node   = ctx->node;
	HANDLE       h_prev = ctx->h_prev;

	free( ctx );
	if ( h_prev != NULL )
	{
		/* outside crit_sect: the superseded worker needs it to notice and exit */
		WaitForSingleObject( h_prev, INFINITE );
		CloseHandle( h_prev );
	}
	return node;
}


DWORD
WINAPI
_thread_format_proc(
		LPVOID lparam
	)
{
	int i = 0;
	int rlt = ST_OK, wp_mode;

	wchar_t device[MAX_PATH];
	_dnode *node;
	_dact  *act;

	node = _worker_begin( lparam );
	dc_open_device( );
	EnterCriticalSection(&crit_sect);

	act = _create_act_thread(node, -1, -1);

	if ( !node || !act || (act->worker_id != (LONG)GetCurrentThreadId( )) )
	{
		LeaveCriticalSection( &crit_sect );
		return 0L;
	}
	wcscpy(device, act->device);
	do
	{
		/* re-validated after every wait outside crit_sect, see _current_act */
		if ( (act = _current_act(device)) == NULL )
		{
			rlt = ST_CANCEL;
			break;
		}
		if ( act->status != ACT_RUNNING )
		{
			break;
		}
		if ( i-- == 0 )
		{
			dc_sync_enc_state(device);
			i = DC_SYNC_EVERY_STEPS - 1;
		}
		wp_mode = act->wp_mode;
		LeaveCriticalSection( &crit_sect );

		rlt = dc_format_step( device, wp_mode );

		EnterCriticalSection( &crit_sect );
		if ( (act = _current_act(device)) == NULL )
		{
			/* superseded: the current worker finishes the formatting */
			rlt = ST_CANCEL;
			break;
		}
		if ( rlt == ST_FINISHED )
		{
			act->status = ACT_STOPPED;
			break;
		}
		if ( ( rlt != ST_OK ) && ( rlt != ST_RW_ERR ) )
		{
			dc_status st;
			/* the device may be gone - no uninitialised mount point in the message */
			if ( dc_get_device_status( device, &st ) != ST_OK ) st.mnt_point[0] = 0;

			__error_s(
				HWND_DESKTOP,
				L"Format error on volume [%s]", rlt, st.mnt_point[0] ? st.mnt_point : device
				);

			act->status = ACT_STOPPED;
			break;
		}
	} while (1);

	if ( rlt == ST_FINISHED )
	{
		_finish_formatting( node );
	}
	LeaveCriticalSection( &crit_sect );

	return 1L;

}


static
DWORD WINAPI
_thread_enc_dec_proc(
		LPVOID lparam
	)
{
	BOOL encrypting;
	int i = 0;
	int rlt, wp_mode;
	int fin_bad = 0, fin_type = 0;  /* bad blocks, reported after the loop */
	int fin_why = BAD_BLOCKS_FINISHED;

	wchar_t device[MAX_PATH];
	_dnode *node;
	_dact *act;

	node = _worker_begin( lparam );
	dc_open_device( );
	EnterCriticalSection( &crit_sect );

	act = _create_act_thread(node, -1, -1);

	if ( !node || !act || (act->worker_id != (LONG)GetCurrentThreadId( )) )
	{
		LeaveCriticalSection( &crit_sect );
		return 0L;
	}

	wcscpy( device, act->device );
	do
	{
		/*
		   re-validated after every wait outside crit_sect (a step or the ST_CANCEL retry
		   delay), see _current_act. Only one worker drives the act.
		*/
		if ( (act = _current_act(device)) == NULL )
		{
			break;
		}
		if ( act->status != ACT_RUNNING )
		{
			if ( act->status == ACT_STOPPED && act->bad_blocks != 0 )
			{
				/* stopped from outside (e.g. unmount) - the act is freed after this,
				   report its bad blocks now. A pause keeps them. */
				fin_bad  = act->bad_blocks;
				fin_type = act->act;
				fin_why  = BAD_BLOCKS_STOPPED;
				act->bad_blocks = 0;
			}
			break;
		}
		if ( i-- == 0 )
		{
			dc_sync_enc_state( device );
			i = DC_SYNC_EVERY_STEPS - 1;
		}
		encrypting = act->act != ACT_DECRYPT;
		wp_mode = act->wp_mode;

		LeaveCriticalSection( &crit_sect );

		rlt = encrypting ?
			dc_enc_step(device, wp_mode) :
			dc_dec_step(device);

		EnterCriticalSection(&crit_sect);
		if ( rlt == ST_RW_ERR )
		{
			/*
			   the driver passed a block with bad sectors (unreadable ones now read as
			   zeros). Counted on the device's act even when this worker was superseded
			   meanwhile (the current worker reports it).
			*/
			_dact *owner = _device_act(device);
			if ( owner != NULL )
			{
				owner->bad_blocks++;
			}
		}
		if ( rlt == ST_OK || rlt == ST_RW_ERR )
		{
			/* the session's skip bitmap is loaded now (kept until a lock / unmount) */
			_dact *owner = _device_act(device);
			if ( owner != NULL )
			{
				owner->stepped = 1;
			}
		}
		if ( (act = _current_act(device)) == NULL )
		{
			/* superseded during this step - if this step finished the transcryption, the
			   current act ends with it (its own next step would only get ST_ERROR) */
			_dact *owner;
			if ( rlt == ST_FINISHED && (owner = _device_act(device)) != NULL &&
				 (owner->status == ACT_RUNNING || owner->status == ACT_PAUSED) )
			{
				fin_bad  = owner->bad_blocks;
				fin_type = owner->act;
				owner->bad_blocks = 0;
				owner->status = ACT_STOPPED;
			}
			break;
		}
		if ( rlt == ST_FINISHED )
		{
			fin_bad  = act->bad_blocks;
			fin_type = act->act;
			act->bad_blocks = 0;  /* reported now; a reused act starts from 0 */
			act->status = ACT_STOPPED;
			break;
		}
		if ( rlt == ST_CANCEL )
		{
			dc_status cst;

			/*
			   a lock (hibernation) frees the allocation bitmap of a skip-unused session; the
			   first step after the unlock would load it again without the shadow copy question.
			   The act pauses instead, the resume asks (_session_check_shadows).
			*/
			if ( dc_get_device_status( device, &cst ) == ST_OK && DC_IS_LOCKED(cst.flags) &&
				 cst.crypt.wp_mode == WP_SKIP_UNUSED )
			{
				act->stepped = 0;
				act->status  = ACT_PAUSED;
				continue;
			}
			/*
			   the step was refused for now, e.g. the volume is locked: retry every 5 s.
			   Wait outside crit_sect (the main timer and the menu handlers need it); the
			   act is re-validated at the top of the loop, it must not be used here.
			*/
			LeaveCriticalSection( &crit_sect );
			Sleep(5000);
			EnterCriticalSection( &crit_sect );
			continue;
		}
		if ( rlt == ST_ERROR && act->status == ACT_STOPPED )
		{
			/* stopped meanwhile (unmount, or a superseded worker's step finished the
			   transcryption): no session any more, not an error - but its bad blocks are
			   still reported, the act is freed after this */
			fin_bad  = act->bad_blocks;
			fin_type = act->act;
			fin_why  = BAD_BLOCKS_STOPPED;
			act->bad_blocks = 0;
			break;
		}
		if ( ( rlt != ST_OK ) && ( rlt != ST_RW_ERR ) )
		{
			dc_status st;
			wchar_t *act_name;

			/* the device may be gone - no uninitialised mount point in the message */
			if ( dc_get_device_status( device, &st ) != ST_OK ) st.mnt_point[0] = 0;
			switch ( act->act )
			{
				case ACT_ENCRYPT:   act_name = L"Encryption";   break;
				case ACT_DECRYPT:   act_name = L"Decryption";   break;
				case ACT_REENCRYPT: act_name = L"Reencryption"; break;
				default:            act_name = L"Operation";    break;
			}
			/* the act is freed after this stop, report its bad blocks now */
			fin_bad  = act->bad_blocks;
			fin_type = act->act;
			fin_why  = BAD_BLOCKS_ERROR;
			act->bad_blocks = 0;
			act->status = ACT_STOPPED;

			__error_s(
				HWND_DESKTOP,
				L"%s error on volume [%s]", rlt, act_name, st.mnt_point[0] ? st.mnt_point : device
				);
			break;
		}
	} while (1);

	dc_sync_enc_state(device);
	LeaveCriticalSection(&crit_sect);

	if ( fin_bad != 0 )
	{
		_show_bad_blocks( device, fin_type, fin_bad, fin_why );
	}
	return 1L;

}


void _clear_act_list( )
{
	list_entry *node = __action.flink;
	list_entry *del = NULL;

	list_entry *head = &__action;

	for ( ;
		node != &__action;		
	)
	{
		_dact *act = contain_record(node, _dact, list);
		/* also an act without a worker (a stop through _create_act_thread, a failed start) */
		if ( ACT_STOPPED == act->status )
		{
			if ( act->h_thread == NULL || WaitForSingleObject(act->h_thread, 0) == WAIT_OBJECT_0 )
			{
				del = node;
				node = node->flink;

				_remove_entry_list(del); 

				if ( act->h_thread != NULL )
				{
					CloseHandle(act->h_thread);
				}
				free(del);
			
				continue;
			}
		}
		node = node->flink;
	}

}


static
_dact *_create_act_thread_locked(
		_dnode *node,
		int     act_type,   // -1 - search
		int     act_status  //
	)
{
	list_entry *item;
	_dact      *act;

	BOOL  exist = FALSE;

	if ( !node )
	{
		return NULL;
	}
	_clear_act_list( );

	for (
		item = __action.flink;
		item != &__action;
		item = item->flink
		)
	{
		act = contain_record(item, _dact, list);
		if ( !wcscmp(act->device, node->mnt.info.device) )
		{
			exist = TRUE;
			if ( act_type == -1 )
			{
				return act;
			} else {
				break;
			}
		}
	}
	if ( act_type != -1 )
	{
		if ( !exist )
		{
			if ( (act = malloc(sizeof(_dact))) == NULL )
			{
				__error_s( __dlg, L"Error creating thread", ST_NOMEM );
				return NULL;
			}
			memset(act, 0, sizeof(_dact));

			act->wp_mode = node->mnt.info.status.crypt.wp_mode;
			wcsncpy( act->device, node->mnt.info.device, MAX_PATH );

			_init_speed_stat( &act->speed );

			/* listed before its worker starts: the worker looks the act up by its device */
			_insert_tail_list(&__action, &act->list);
		}
		/*
		   every start / pause / stop through here supersedes the act's previous worker: it
		   no longer matches worker_id and exits at its next check (_current_act). Its handle
		   goes to the new worker (which waits for it, _worker_begin), or stays the act's
		   thread when none starts, so that _clear_act_list waits for it as well.
		*/
		HANDLE h_prev = act->h_thread;

		/*
		   act->bad_blocks is kept across pause / resume and a change of direction: sectors
		   zeroed in one direction stay lost. It is reset when it is reported.
		*/
		InterlockedExchange( &act->worker_id, 0 );
		act->h_thread = NULL;
		act->status   = act_status;
		act->act      = act_type;

		if ( act_status == ACT_RUNNING )
		{
			LPTHREAD_START_ROUTINE proc = NULL;
			DWORD                  tid  = 0;
			int                    rlt  = 0;
			_worker_ctx           *ctx  = NULL;

			switch (act_type)
			{
				case ACT_REENCRYPT:
				case ACT_ENCRYPT:
				case ACT_DECRYPT:   proc = _thread_enc_dec_proc; break;
				case ACT_FORMAT:    proc = _thread_format_proc;  break;
			}
			if ( proc != NULL && (ctx = malloc(sizeof(_worker_ctx))) != NULL )
			{
				ctx->node   = node;
				ctx->h_prev = h_prev;

				act->h_thread = CreateThread(
					NULL, 0, proc, ctx, CREATE_SUSPENDED, &tid
					);
			}
			if ( act->h_thread == NULL )
			{
				rlt = (proc == NULL) ? ERROR_INVALID_PARAMETER : (ctx == NULL) ? ERROR_NOT_ENOUGH_MEMORY : GetLastError( );
			} else
			{
				/* published before the worker runs, it checks it first */
				InterlockedExchange( &act->worker_id, (LONG)tid );
				SetThreadPriority(act->h_thread, THREAD_PRIORITY_LOWEST);

				if ( ResumeThread(act->h_thread) == (DWORD)-1 )
				{
					rlt = GetLastError( );

					/* never ran: discard it */
					InterlockedExchange( &act->worker_id, 0 );
					TerminateThread( act->h_thread, 0 );
					CloseHandle( act->h_thread );
					act->h_thread = NULL;
				} else
				{
					h_prev = NULL; /* owned by the new worker */
					ctx    = NULL; /* freed by the new worker */
				}
			}
			if ( ctx != NULL )
			{
				free( ctx );
			}
			if ( act->h_thread == NULL )
			{
				/* not started: the superseded worker (may be NULL) stays the act's thread */
				act->h_thread = h_prev;

				if ( exist )
				{
					/* the act stays listed (its progress is kept), resumable */
					act->status = ( act_type != ACT_FORMAT ) ? ACT_PAUSED : ACT_STOPPED;
				} else
				{
					_remove_entry_list( &act->list );
					free( act );
				}
				__error_s( __dlg, L"Error creating thread", -rlt );
				return NULL;
			}
		} else
		{
			act->h_thread = h_prev; /* the superseded worker, see above */
		}
		return act;
	}
 	return NULL;

}


/*
   the act list (__action) is shared by the UI thread and the workers: every lookup may prune
   it (_clear_act_list) and a start inserts / removes acts, so always under crit_sect (it is
   recursive - the workers and the main timer call this with it held already)
*/
_dact *_create_act_thread(
		_dnode *node,
		int     act_type,   // -1 - search
		int     act_status  //
	)
{
	_dact *act;

	EnterCriticalSection( &crit_sect );
	act = _create_act_thread_locked( node, act_type, act_status );
	LeaveCriticalSection( &crit_sect );

	return act;
}
