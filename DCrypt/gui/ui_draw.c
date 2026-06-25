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
#include <commctrl.h>

#include "main.h"
#include "ui_draw.h"

int _draw_proc(
		int    message,
		LPARAM lparam
	)
{
	switch ( message )
	{
		case WM_DRAWITEM : 
		{
			_draw_static((LPDRAWITEMSTRUCT)lparam);			
			return 1L;
		}
		break;

		case WM_MEASUREITEM:
		{
			MEASUREITEMSTRUCT *item = pv(lparam);
			if ( item->CtlType != ODT_LISTVIEW )
			{
				item->itemHeight -= 3;
			}
			return 1L;
		}
		break;

		/*case WM_NOTIFY :
		{
			if ( wparam == IDT_INFO )
			{
				int code = ((NMHDR *)lparam)->code;
				__msg_i( hwnd, L"static_proc: %d", code );
			}
		}
		break;*/
	}
	return -1;
}


void _fill(
		HDC      dc,
		RECT    *rc,
		COLORREF cl
	)
{
	HGDIOBJ brsh;

	SetDCBrushColor(dc, cl); 
	SetBkMode(dc, TRANSPARENT);

	brsh = GetStockObject(DC_BRUSH);
	FillRect(dc, rc, brsh);

	return;
}


void _draw_listview(
		LPDRAWITEMSTRUCT itst
	)
{
	DRAWTEXTPARAMS dtp         = { sizeof(dtp) };
	LVCOLUMN       lvc         = { sizeof(lvc) };
	wchar_t        s_text[200] = { 0 };
	int            cx, cy, k   = 0;
	int            offset      = 0;
	int            icon;
	BOOL           is_root;
	int            col_cnt     = Header_GetItemCount( ListView_GetHeader( itst->hwndItem ) );
	LVITEM         lvitem      = { LVIF_TEXT | LVIF_PARAM, itst->itemID, 0, 0, 0, s_text, countof(s_text) };
	COLORREF       bgcolor     = ListView_GetBkColor( itst->hwndItem );
	int            scroll_x    = GetScrollPos( itst->hwndItem, SB_HORZ );

	ListView_GetItem( itst->hwndItem, &lvitem );
	is_root = _is_root_item( lvitem.lParam );

	if ( ( itst->itemState & ODS_SELECTED ) && IsWindowEnabled( itst->hwndItem ) /*&& ( lvitem.lParam != NULL )*/ )
	{
		if ( GetFocus( ) == itst->hwndItem )
		{
			bgcolor = CL_WHITE;
		} else {
			bgcolor = _cl( COLOR_BTNFACE, 80 );
		}
	}
	if ( is_root )
	{
		bgcolor = _cl( COLOR_BTNSHADOW, 60 );
	}
	if ( _is_marked_item(lvitem.lParam) )
	{
		bgcolor = _cl( COLOR_BTNSHADOW, 35 );
	}

	_fill( itst->hDC, &itst->rcItem, bgcolor );

	for ( ; k < col_cnt; k++ )
	{
		lvc.mask = LVCF_FMT | LVCF_WIDTH | LVCF_IMAGE;
		ListView_GetColumn( itst->hwndItem, k, &lvc );

		itst->rcItem.left  = k ? itst->rcItem.right : -scroll_x;
		itst->rcItem.right = itst->rcItem.left + lvc.cx;

		lvitem.iItem       = itst->itemID; 
		lvitem.iSubItem    = k;

		ListView_GetItem( itst->hwndItem, &lvitem );
		dtp.iLeftMargin = dtp.iRightMargin = 5;		

		if ( (itst->rcItem.left == -scroll_x) && _is_icon_show( itst->hwndItem, k ) )
		{
			ImageList_GetIconSize( __dsk_img, &cx, &cy );
			offset = lvitem.lParam && !is_root ? 25 : 3;

			itst->rcItem.left += offset + cy + ( lvitem.lParam && !is_root ? 8 : 4 );
			icon = 0;

			if (! is_root )
			{
				if ( _is_splited_item(lvitem.lParam) ) icon = 1;
				if ( _is_cdrom_item(lvitem.lParam) )   icon = 2;
			}

			ImageList_Draw(
				__dsk_img, icon, itst->hDC, offset - scroll_x, itst->rcItem.top + 3, ILD_TRANSPARENT
				);
		} else 
		{
			offset = 0;
		}
		if ( offset && is_root )
		{
			DrawState(
				itst->hDC, 0, NULL, (LPARAM)s_text, 0, 
				itst->rcItem.left+5, itst->rcItem.top, 0, 0, DST_PREFIXTEXT | DSS_MONO
				);
		} else 
		{
			if ( wcslen(s_text) != 0 ) 
			{
				COLORREF text_color = GetSysColor( COLOR_WINDOWTEXT );

				if ( !_is_active_item(lvitem.lParam) )
				{
					text_color = GetSysColor( COLOR_GRAYTEXT );
				}
				SetTextColor( itst->hDC, text_color );

				if ( k >= 4 )
				{
					SelectObject( itst->hDC, __font_bold );
				}
				if ( !IsWindowEnabled( itst->hwndItem ) )
				{
					SetTextColor( itst->hDC, GetSysColor(COLOR_GRAYTEXT) );

					DrawTextEx(
						itst->hDC, s_text, -1, &itst->rcItem,
						DT_END_ELLIPSIS | ((lvc.fmt & LVCFMT_RIGHT) ? DT_RIGHT : FALSE), &dtp
						);
				} else 
				{
					DrawTextEx(
						itst->hDC, s_text, -1, &itst->rcItem,
						DT_END_ELLIPSIS | ((lvc.fmt & LVCFMT_RIGHT) ? DT_RIGHT : FALSE), &dtp
						);
					/*
					if ( GetFocus( ) == itst->hwndItem )
					{
						DrawFocusRect( itst->hDC, &itst->rcItem );
					}
					*/
				}
			}
		}
	}							
}


void _draw_combobox(
		LPDRAWITEMSTRUCT itst
	)
{
	TEXTMETRIC tm;

	wchar_t data[MAX_PATH];
	int x,y;

	DWORD txc = COLOR_WINDOWTEXT;
	DWORD bgc = _cl(COLOR_BTNFACE, LGHT_CLR);

	/* Handle invalid item ID (can be -1 for empty combo or focus rect) */
	if (itst->itemID == (UINT)-1) {
		_fill(itst->hDC, &itst->rcItem, _cl(COLOR_BTNFACE, LGHT_CLR));
		return;
	}

	if (itst->itemState & ODS_SELECTED) {
		bgc = _cl(COLOR_BTNSHADOW, DARK_CLR-15);
		txc = COLOR_HIGHLIGHTTEXT;

	}
	if (itst->itemState & ODS_DISABLED) {
		bgc = _cl(COLOR_BTNFACE, FALSE);
		txc = COLOR_GRAYTEXT;

	}

	SetTextColor(itst->hDC, GetSysColor(txc));
	SetBkColor(itst->hDC, bgc);

	GetTextMetrics(itst->hDC, &tm);

	y = (itst->rcItem.bottom + itst->rcItem.top - tm.tmHeight) / 2;
	x = LOWORD(GetDialogBaseUnits( )) / 4;

	data[0] = L'\0';
	SendMessage(itst->hwndItem, CB_GETLBTEXT, itst->itemID, (LPARAM)data);
	ExtTextOut(itst->hDC, 3*x, y, ETO_CLIPPED | ETO_OPAQUE, &itst->rcItem,
		data, (u32)(wcslen(data)), NULL);

}


void _draw_tabs(
		LPDRAWITEMSTRUCT itst
	)
{	
	DrawState(itst->hDC, NULL, NULL, 
		(LPARAM)NULL, 0, itst->rcItem.left, itst->rcItem.top, 0, 0, DST_PREFIXTEXT);

	DrawEdge(itst->hDC, &itst->rcItem, BDR_SUNKENOUTER, 0);


}


void _draw_static(
		LPDRAWITEMSTRUCT itst
	)
{
	UINT edge   = BDR_RAISEDINNER;
	UINT state  = DSS_NORMAL;
	UINT border = BF_RECT;

	DRAWTEXTPARAMS tp = { sizeof(tp) };
	WINDOWINFO wi;
	RECT rc;

	_wnd_data *gwl;
	_tab_data *tab;

	wchar_t data[MAX_PATH];
	int x = 6, y = 3;
	char curr;	

	if ( !itst ) return;
	switch ( itst->CtlType )
	{
		case ODT_LISTVIEW: _draw_listview(itst); break;
		case ODT_COMBOBOX: _draw_combobox(itst); break;
		case ODT_TAB:      _draw_tabs(itst);     break;

		case ODT_BUTTON:

        if ( itst->itemState & ODS_DISABLED ) state = DSS_DISABLED;
        /* Check for selected (pressed) OR checked (toggle) state */
        if ( (itst->itemState & ODS_SELECTED) ||
             (SendMessage(itst->hwndItem, BM_GETCHECK, 0, 0) == BST_CHECKED) )
		{
			edge = BDR_SUNKENOUTER;
			x++; y++;
        }
		itst->rcItem.top++;

		GetWindowText( itst->hwndItem, data, MAX_PATH );
		GetClientRect( itst->hwndItem, &rc );

		gwl = wnd_get_long( itst->hwndItem, GWL_USERDATA );
		tab = wnd_get_long( GetParent(itst->hwndItem), GWL_USERDATA );

		curr = tab && ( tab->h_curr == itst->hwndItem );

		if ( gwl )
		{
			if ( !gwl->dlg[0] )
			{
				itst->rcItem.right  = itst->rcItem.left + 13;
				itst->rcItem.bottom = itst->rcItem.top  + 13;

				_fill( itst->hDC, &rc, _cl(COLOR_BTNFACE, FALSE) );
				_fill( itst->hDC, &itst->rcItem, /* (itst->itemState & ODS_FOCUS) ? _cl(COLOR_BTNFACE, FALSE) : */ _cl(COLOR_BTNFACE, LGHT_CLR) );

				GetWindowText(itst->hwndItem, data, MAX_PATH);
				if ( gwl->state )
				{
					ImageList_DrawEx(
						__img, 0, itst->hDC, itst->rcItem.right - 11, 2, 0, 0, CLR_NONE, GetSysColor(COLOR_BTNSHADOW), ILD_BLEND
					);
				}
				DrawEdge(
					itst->hDC, &itst->rcItem, BDR_SUNKENOUTER, border
					);
				DrawState(
					itst->hDC, NULL, NULL, (LPARAM)data, 0, itst->rcItem.right+4, 0, 0, 0, DST_PREFIXTEXT | state
					);

				if ( itst->itemState & ODS_FOCUS )
				{
					rc.bottom  = itst->rcItem.bottom - itst->rcItem.top + 2;					
					rc.left   += itst->rcItem.right + 2;

					DrawFocusRect( itst->hDC, &rc );
				}
				return;
			} else 
			{ 
				if ( curr )
				{							
					edge = BDR_SUNKENOUTER;
					x++; y++;
				} else {
					border = BF_FLAT;
				}
			}
		}

		_fill( itst->hDC, &itst->rcItem, (itst->itemState & ODS_FOCUS ) ?
			_cl( COLOR_BTNFACE, DARK_CLR ) :
			_cl( COLOR_BTNFACE, FALSE ) );

		DrawState( itst->hDC, NULL, NULL, (LPARAM)data, 0, x, y, 0, 0, DST_PREFIXTEXT | state );
		if ( itst->itemState & ODS_FOCUS )
		{
			modify_rect( rc, 1, 2, -2, -2 );
			if ( (itst->itemState & ODS_SELECTED) ||
			     (SendMessage(itst->hwndItem, BM_GETCHECK, 0, 0) == BST_CHECKED) )
			{
				modify_rect( rc, 1, 1, 1, 1 );
			}
			DrawFocusRect( itst->hDC, &rc );
		}
		DrawEdge(itst->hDC, &itst->rcItem, edge, border);
		break;

		case ODT_STATIC:
		{
			GetWindowInfo(itst->hwndItem, &wi);
			GetWindowText(itst->hwndItem, data, MAX_PATH);

			if ( data[0] == L'#' )
			{
				HWND hParent = GetParent(itst->hwndItem);
				HWND hGrandParent = hParent ? GetParent(hParent) : NULL;

				/* Use grandparent if available, otherwise fall back to parent dialog */
				if (hGrandParent && IsWindow(hGrandParent)) {
					GetWindowRect(hGrandParent, &rc);
				} else if (hParent && IsWindow(hParent)) {
					GetClientRect(hParent, &rc);
				} else {
					GetClientRect(itst->hwndItem, &rc);
					rc.right += 20; /* fallback padding */
				}

				itst->rcItem.right = rc.right - rc.left - 3;
				itst->rcItem.top = itst->rcItem.left = 1;

				_fill(itst->hDC, &itst->rcItem, _cl(COLOR_BTNSHADOW, DARK_CLR - 7));

				tp.iLeftMargin   += 10;
				itst->rcItem.top += 1;

				DrawTextEx(itst->hDC, data + 1, -1, &itst->rcItem, DT_END_ELLIPSIS, &tp);
			}
			else 
			{
				if ( (wi.dwStyle & SS_SUNKEN) == 0 )
				{
					DrawEdge(itst->hDC, &itst->rcItem, edge, border);				
				}
			}
		}
		break;
	}
}


