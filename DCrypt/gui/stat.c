/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
    * DavidXanatos <info@diskcryptor.org>
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
#include "stat.h"

#include "threads.h"

#include "dc_header.h"
#include "prc_header.h"

void _get_time_period(
		__int64  begin,
		wchar_t *display,
		BOOL     abs
	)
{
	LARGE_INTEGER curr;
	SYSTEMTIME st;
	FILETIME ft;

	int j = 0;

	if (! abs )
	{
		GetSystemTimeAsFileTime(&ft);
		curr.HighPart = ft.dwHighDateTime;
		curr.LowPart = ft.dwLowDateTime;
			
		curr.QuadPart -= begin;
	} else {
		curr.QuadPart = begin * 10000000;
	}

	ft.dwHighDateTime = curr.HighPart;
	ft.dwLowDateTime  = curr.LowPart;

	FileTimeToSystemTime( &ft, &st );

	if ( st.wHour ) {
		j += _snwprintf(display+j, 8, L"%d hr.%s", st.wHour, st.wMinute ? L", " : STR_NULL);
	}
	if ( st.wMinute ) {
		j += _snwprintf(display+j, 8, L"%d min.",  st.wMinute);
	}
	if ( st.wSecond && !st.wHour ) {
		j += _snwprintf(display+j, 9, L"%s%d sec.", st.wMinute ? L", " : STR_NULL, st.wSecond);
	}	
	if ( j != 0 ) display[j] = '\0';

}


void _init_speed_stat( 
		_dspeed *speed 
	)
{
	FILETIME time;
	int k = 0;

	for ( ; 
		k < SPEED_QUANTS; 
		speed->speed_stat[k++] = -1 
		);

	GetSystemTimeAsFileTime( &time );

	speed->t_begin.HighPart = time.dwHighDateTime;
	speed->t_begin.LowPart  = time.dwLowDateTime;

}


int _speed_stat_event(
		wchar_t *s_speed,
		size_t   chars,
		_dspeed *speed,
		__int64  tmp_size,
		BOOL     is_running
	)
{
	FILETIME ft;
	BOOL     init = FALSE;

	__int64 last_size = 0;
	int     k;

	for ( k = 0; k < SPEED_EVENT_QUANTS; k++ )
	{
		last_size += speed->speed_stat[k];
		if (speed->speed_stat[k] == -1)
		{
			last_size = 0;
			init = TRUE;

			break;
		}
	}
	if ( !init && is_running )
	{
		__int64 tm_b = speed->time_stat[SPEED_EVENT_QUANTS - 1].QuadPart;
		__int64 tm_e = speed->time_stat[0].QuadPart;

		last_size = _abs64((__int64)(last_size / (( (double)( tm_b - tm_e ) ) / 10000000 )));

		_snwprintf(
			s_speed, chars, L"%.1f mb/sec.", (double) last_size / 1024 / 1024
			);
	} else {
		_snwprintf(
			s_speed, chars, STR_EMPTY
		);

	}
	for ( k = 0; k < SPEED_EVENT_QUANTS - 1; k++ )
	{
		speed->speed_stat[k] = speed->speed_stat[k + 1];
		speed->time_stat[k].QuadPart = speed->time_stat[k + 1].QuadPart;
	}
	GetSystemTimeAsFileTime(&ft);		

	speed->speed_stat[SPEED_EVENT_QUANTS - 1] = tmp_size - speed->tmp_size;
	speed->tmp_size = tmp_size;

	speed->time_stat[SPEED_EVENT_QUANTS - 1].HighPart = ft.dwHighDateTime;
	speed->time_stat[SPEED_EVENT_QUANTS - 1].LowPart  = ft.dwLowDateTime;

	return (int) last_size / 1024 / 1024;

}


static
int _speed_stat_timer(
		wchar_t *s_speed,
		size_t   chars,
		_dspeed *speed,
		__int64  tmp_size,
		BOOL     is_running
	)
{
	BOOL init = FALSE;

	__int64 last_size = 0;
	int k;

	for ( k = 0; k < SPEED_TIMER_QUANTS; k++ )
	{
		last_size += speed->speed_stat[k];
		if (speed->speed_stat[k] == -1)
		{
			last_size = 0;
			init = TRUE;

			break;
		}
	}
	if ( !init && is_running )
	{
		last_size = _abs64(
				( last_size / SPEED_TIMER_QUANTS ) * 
				( 1000 / _tmr_elapse[PROC_TIMER] )
			);

		_snwprintf(
			s_speed, chars, L"%.1f mb/sec.", (double) last_size / 1024 / 1024
			);
	} else {
		_snwprintf(
			s_speed, chars, STR_EMPTY
		);

	}
	for ( k = 0; k < SPEED_TIMER_QUANTS - 1; k++ )
	{
		speed->speed_stat[k] = speed->speed_stat[k + 1];
	}
	speed->speed_stat[SPEED_TIMER_QUANTS - 1] = tmp_size - speed->tmp_size;
	speed->tmp_size = tmp_size;

	return (int) last_size / 1024 / 1024;

}


static
void _update_act_info( 
		HWND    hwnd,
		_dnode *node,
		_dact  *act
	)
{
	HWND h_sector = GetDlgItem( hwnd, IDC_STATIC_SECTOR );

	wchar_t s_estimated[MAX_PATH] = { STR_EMPTY };
	wchar_t s_elapsed[MAX_PATH]   = { STR_EMPTY };

	wchar_t s_speed[MAX_PATH]     = { STR_EMPTY };
	wchar_t s_done[MAX_PATH]      = { STR_EMPTY };

	wchar_t s_sectors[MAX_PATH];
	wchar_t s_old[MAX_PATH];

	__int64 done;
	__int64 sectors;

	int new_pos;
	int speed;
	int j = 0;

	dc_status *status = &node->mnt.info.status;
	dc_get_device_status( node->mnt.info.device, status );

	new_pos = (int)( status->tmp_size / ( status->dsk_size / PRG_STEP ) );
	sectors = status->tmp_size / 512;

	if ( act->act == ACT_DECRYPT )
	{
		new_pos = PRG_STEP - new_pos;
		sectors = status->dsk_size / 512 - sectors;
		done = status->dsk_size - status->tmp_size;
	} else 
	{
		done = status->tmp_size;
	}
	dc_format_byte_size( s_done, countof(s_done), done );
		
	_get_time_period( act->speed.t_begin.QuadPart, s_elapsed, FALSE );

	speed = _speed_stat_timer( s_speed, countof(s_speed), &act->speed, status->tmp_size, act->status == ACT_RUNNING );
					
	if ( speed != 0 )
	{
		_get_time_period( ( ( status->dsk_size - done ) / 1024 / 1024 ) / speed, s_estimated, TRUE );					
	}

	j = _snwprintf( s_sectors, countof(s_sectors), L"Sector: %I64d\t\t", sectors );
	j = _snwprintf( s_sectors+j, countof(s_sectors)-j, L"Total Sectors: %I64d", status->dsk_size / 512 );

	_list_set_item_text( __lists[HMAIN_ACT], 0, 1, _wcslwr(s_done) );
	_list_set_item_text( __lists[HMAIN_ACT], 1, 1, ACT_RUNNING == act->status ? s_speed : STR_EMPTY );

	if ( act->status == ACT_RUNNING )
	{
		_list_set_item_text( __lists[HMAIN_ACT], 0, 3, s_estimated );
		_list_set_item_text( __lists[HMAIN_ACT], 1, 3, s_elapsed );
	}
	GetWindowText( h_sector, s_old, countof(s_old) );

	if ( wcscmp( s_old, s_sectors ) ) 
	{
		SetWindowText( h_sector, s_sectors );
	}
	SendMessage(
		GetDlgItem( hwnd, IDC_COMBO_PASSES ), CB_SETCURSEL, act->wp_mode, 0
		);

	SendMessage(
		GetDlgItem( hwnd, IDC_PROGRESS ), PBM_SETPOS, (WPARAM)new_pos, 0
		);
					
}


void _update_info_table( 
		BOOL iso_info
	)
{
	HWND		 h_tab	= GetDlgItem( __dlg, IDT_INFO );
	
	_wnd_data	*wnd	= wnd_get_long( h_tab, GWL_USERDATA );
	_dnode		*node	= pv( _get_sel_item( __lists[HMAIN_DRIVES] ) );
	_dact		*act	= _create_act_thread( node, -1, -1 );	

	BOOL		 idt_inf_enb = FALSE;
	BOOL		 idt_act_enb = FALSE;
	BOOL		 crypt_info;
	wchar_t      buff[96], buff2[32];

	int k = 0;

	if ( SendMessage(
			GetDlgItem( wnd->dlg[1], IDC_COMBO_PASSES), CB_GETDROPPEDSTATE, 0, 0 )
		 ) 
	{
		return;
	}
	for ( ; k < 2; k++ )
	{
		_list_set_item_text( __lists[HMAIN_ACT], k, 1, STR_EMPTY );
		_list_set_item_text( __lists[HMAIN_ACT], k, 3, STR_EMPTY );
	}

	if ( ListView_GetSelectedCount( __lists[HMAIN_DRIVES] ) && node )
	{
		if ( !node->is_root )
		{
			int is_ssd = dc_is_device_ssd(node->mnt.info.w32_device);

			_list_set_item_text( __lists[HMAIN_INFO], 0, 1, node->mnt.info.w32_device );
			_list_set_item_text( __lists[HMAIN_INFO], 1, 1, node->mnt.info.device );
			_list_set_item_text( __lists[HMAIN_INFO], 2, 1, STR_NULL );

			crypt_info = node->mnt.info.status.flags & F_ENABLED;

			_list_set_item_text(
				__lists[HMAIN_INFO], 3, 1, !crypt_info ? STR_EMPTY : _get_text_name( node->mnt.info.status.crypt.cipher_id, cipher_names )
				);
	
			if ( crypt_info )
			{
				//wchar_t *kdf_name = _get_text_name(node->mnt.info.status.crypt.head_kdf, kdf_names);
				//_list_set_item_text( __lists[HMAIN_INFO], 4, 1, kdf_name ? kdf_name : STR_EMPTY); 
				if (node->mnt.info.status.crypt.head_kdf > 0) {
					u32 memory_cost, time_cost;
					argon2_mk_params_um(node->mnt.info.status.crypt.head_kdf, &memory_cost, &time_cost, NULL);
					_snwprintf(buff, countof(buff), L"Argon2id v1.3 [%dMiB, t=%d]", memory_cost / 1024, time_cost);
					_list_set_item_text( __lists[HMAIN_INFO], 4, 1, buff );
				} else {
					_list_set_item_text( __lists[HMAIN_INFO], 4, 1, IDS_PRF_NAME );
				}

				if (node->mnt.info.status.crypt.version == DC_HDR_VERSION_2) {
					_format_hdr_size(node->mnt.info.status.crypt.head_len, buff2, countof(buff2), TRUE);
					wcscpy(buff, L"v2 (");
					wcscat_s(buff, countof(buff), buff2);
					if (node->mnt.info.status.flags & F_HEAD_BACKUP) {
						wcscat_s(buff, countof(buff), L", backedup");
					}
					wcscat_s(buff, countof(buff), L")");
				}
				else {
					wcscpy(buff, L"v1");
				}

				wcscat_s(buff, countof(buff), L" [");
				if (node->mnt.info.status.flags & F_PROTECT_DCSYS) {
					wcscat_s(buff, countof(buff), L"storage: file");
				} else if (!(node->mnt.info.status.flags & F_CDROM)){
					wcscat_s(buff, countof(buff), L"storage: part. end");
				}
				wcscat_s(buff, countof(buff), L"]");

				_list_set_item_text( __lists[HMAIN_INFO], 5, 1, buff );
			}
			else
			{
				_list_set_item_text( __lists[HMAIN_INFO], 4, 1, STR_EMPTY );
				_list_set_item_text( __lists[HMAIN_INFO], 5, 1, STR_EMPTY );
			}

			idt_inf_enb = TRUE;

			if ( act )
			{
				EnableWindow(GetDlgItem(
					wnd->dlg[1], IDC_STATIC_PASSES_LIST), ACT_DECRYPT != act->act && !is_ssd && act->wp_mode != WP_SKIP_UNUSED
					);
				EnableWindow(GetDlgItem(
					wnd->dlg[1], IDC_STATIC_SECTOR), ACT_RUNNING == act->status
					);
				EnableWindow(GetDlgItem(
					wnd->dlg[1], IDC_COMBO_PASSES), ACT_DECRYPT != act->act && !is_ssd && act->wp_mode != WP_SKIP_UNUSED
					);
				EnableWindow(GetDlgItem(
					wnd->dlg[1], IDB_ACT_PAUSE), ACT_RUNNING == act->status
					);
				EnableWindow(GetDlgItem(
					wnd->dlg[1], IDC_ACT_TABLE), ACT_RUNNING == act->status
					);
				SetWindowText(GetDlgItem(
					wnd->dlg[1], IDB_ACT_PAUSE), ACT_FORMAT == act->act ? L"Cancel" : L"Pause"
					);

				_update_act_info( wnd->dlg[1], node, act );
				idt_act_enb = TRUE;
					
			}
		}
	}
	{
		TCITEM tab_item = { TCIF_TEXT };
		NMHDR  mhdr = { 0, 0, TCN_SELCHANGE };

		int cnt = TabCtrl_GetItemCount( h_tab );
		int sel = TabCtrl_GetCurSel( h_tab );

		if ( !idt_act_enb && cnt == 2 )
		{
			TabCtrl_DeleteItem( h_tab, 1 );
			sel = 0;
		}
		if ( idt_act_enb && cnt == 1 )
		{		
			tab_item.pszText = L"Action";
			TabCtrl_InsertItem( h_tab, 1, &tab_item );
			sel = 1;
		}
		TabCtrl_SetCurSel( h_tab, sel );
		SendMessage( __dlg, WM_NOTIFY, IDT_INFO, (LPARAM)&mhdr );

	}
	if ( !idt_inf_enb )
	{
		for ( k = 0; k < 6; k++ ) 
		{
			_list_set_item_text( __lists[HMAIN_INFO], k, 1, STR_NULL );
		}
	}
	if ( !idt_act_enb )
	{
		SendMessage( GetDlgItem(wnd->dlg[1], IDC_COMBO_PASSES), CB_SETCURSEL, 0, 0 );
		SendMessage( GetDlgItem(wnd->dlg[1], IDC_PROGRESS), PBM_SETPOS, 0, 0 );
		SetWindowText( GetDlgItem(wnd->dlg[1], IDC_STATIC_SECTOR), NULL );
	}
}


