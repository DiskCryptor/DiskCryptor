#ifndef _PRCCOMMON_
#define _PRCCOMMON_

void update_entropy_tooltip(
	HWND hwnd, 
	HWND hCtrl,	
	int entropy
);

INT_PTR
CALLBACK
_tab_proc(
		HWND   hwnd,
		UINT   message,
		WPARAM wparam,
		LPARAM lparam
	);

#endif