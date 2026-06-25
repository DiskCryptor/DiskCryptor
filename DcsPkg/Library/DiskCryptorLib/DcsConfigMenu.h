#ifndef _DCSCONFIGMENU_H_
#define _DCSCONFIGMENU_H_

#include <Uefi.h>

VOID
DcsShowHelp(
	VOID
);

// Returns TRUE if values were applied (Enter), FALSE if discarded (Esc)
BOOLEAN
DcsConfigMenuShow(
	VOID
);

// Save current configuration to the config file
EFI_STATUS
DCAuthStoreConfig(
	VOID
);

#endif // _DCSCONFIGMENU_H_
