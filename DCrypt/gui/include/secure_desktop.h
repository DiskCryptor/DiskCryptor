/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2019-2026
    * DavidXanatos <info@diskcryptor.org>
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

#ifndef _SECURE_DESKTOP_H_
#define _SECURE_DESKTOP_H_

#include <windows.h>

/* Initialize secure desktop subsystem - call once at startup */
void secure_desktop_init(void);

/* Cleanup secure desktop subsystem - call once at shutdown */
void secure_desktop_cleanup(void);

/* Check if current thread is running on secure desktop */
BOOL is_thread_in_secure_desktop(DWORD dwThreadID);

/* Check if secure desktop mode is currently active */
BOOL is_secure_desktop_active(void);

/*
 * Display a dialog on a secure desktop if CONF_SECURE_DESKTOP is enabled.
 * Falls back to normal DialogBoxParam if secure desktop is disabled or fails.
 *
 * Parameters are identical to DialogBoxParam.
 */
INT_PTR secure_desktop_dialog_box_param(
    HINSTANCE hInstance,
    LPCWSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam
);

#endif /* _SECURE_DESKTOP_H_ */
