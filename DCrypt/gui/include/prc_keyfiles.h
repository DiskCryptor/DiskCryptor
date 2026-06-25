#ifndef _KEYFILES_
#define _KEYFILES_

#include "linklist.h"

typedef struct __list_key_files
{
	list_entry next;
	wchar_t path[MAX_PATH];
	int     is_virtual;      // TRUE if this is a virtual keyfile
	u8     *virtual_data;    // pointer to virtual keyfile data (if is_virtual)
	u32     virtual_size;    // size of virtual keyfile data

} _list_key_files;

// Keyfile state - holds a keyfile list and its mixing mode
typedef struct _keyfiles_state
{
	list_entry head;
	int        mix_mode;
} keyfiles_state;

extern _colinfo _keyfiles_headers[ ];

// Initialize a keyfiles_state structure
void _keyfiles_init(
		keyfiles_state *state
	);

// Wipe and free all keyfiles in a state
void _keyfiles_wipe(
		keyfiles_state *state
	);

// Count keyfiles in a state
int _keyfiles_count(
		keyfiles_state *state
	);

// Get first keyfile in a state (NULL if empty)
_list_key_files *_first_keyfile(
		keyfiles_state *state
	);

// Get next keyfile (NULL if no more)
_list_key_files *_next_keyfile(
		_list_key_files *keyfile,
		keyfiles_state *state
	);

// Open keyfiles dialog to edit a keyfiles_state
// allow_virtual: if FALSE, disables "Add Virtual" button (prevents infinite recursion)
void _dlg_keyfiles(
		HWND hwnd,
		keyfiles_state *state,
		BOOL allow_virtual
	);

// Check if the keyfile state contains any virtual keyfiles
int _keyfiles_has_virtual(
		keyfiles_state *state
	);

#endif
