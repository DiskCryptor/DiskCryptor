#ifndef _UNMOUNT_TIMER_H_
#define _UNMOUNT_TIMER_H_

#define UNMOUNT_TIMEOUT_UNIT_SEC   0
#define UNMOUNT_TIMEOUT_UNIT_MIN   1
#define UNMOUNT_TIMEOUT_UNIT_HOUR  2

#define MAX_UNMOUNT_TIMERS 32

typedef struct _unmount_timer_entry {
	wchar_t device[MAX_PATH];
	wchar_t mnt_point[MAX_PATH];
	DWORD   timeout_ms;
	DWORD   start_tick;
	BOOL    active;
} _unmount_timer_entry;

void _unmount_timer_init(void);
void _unmount_timer_cleanup(void);

void _unmount_timer_add(const wchar_t *device, const wchar_t *mnt_point, DWORD timeout_ms);

void _unmount_timer_remove(const wchar_t *device);

void _unmount_timer_cancel_all(void);

void _unmount_timer_purge_unmounted(void);

void _unmount_timer_check(void);

DWORD _unmount_timer_calc_ms(int value, int unit);

void _unmount_timer_save_defaults(int value, int unit);
void _unmount_timer_load_defaults(int *value, int *unit);

void _dlg_set_unmount_timer(HWND hwnd, const wchar_t *device, const wchar_t *mnt_point);

#endif
