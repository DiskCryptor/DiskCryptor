#include <windows.h>

#include "main.h"
#include "unmount_timer.h"

static _unmount_timer_entry unmount_timers[MAX_UNMOUNT_TIMERS];
static int                  unmount_timer_count;
static CRITICAL_SECTION     unmount_timer_cs;
static BOOL                 unmount_timer_inited;

void _unmount_timer_init(void)
{
	if (!unmount_timer_inited)
	{
		InitializeCriticalSection(&unmount_timer_cs);
		memset(unmount_timers, 0, sizeof(unmount_timers));
		unmount_timer_count = 0;
		unmount_timer_inited = TRUE;
	}
}

void _unmount_timer_cleanup(void)
{
	if (unmount_timer_inited)
	{
		DeleteCriticalSection(&unmount_timer_cs);
		unmount_timer_inited = FALSE;
	}
}

void _unmount_timer_add(const wchar_t *device, const wchar_t *mnt_point, DWORD timeout_ms)
{
	int i;
	if (!unmount_timer_inited) return;

	EnterCriticalSection(&unmount_timer_cs);

	if (unmount_timer_count >= MAX_UNMOUNT_TIMERS)
	{
		LeaveCriticalSection(&unmount_timer_cs);
		return;
	}

	for (i = 0; i < unmount_timer_count; i++)
	{
		if (wcscmp(unmount_timers[i].device, device) == 0)
		{
			unmount_timers[i].timeout_ms = timeout_ms;
			unmount_timers[i].start_tick = GetTickCount();
			unmount_timers[i].active = TRUE;
			LeaveCriticalSection(&unmount_timer_cs);
			return;
		}
	}

	wcscpy_s(unmount_timers[unmount_timer_count].device, MAX_PATH, device);
	wcscpy_s(unmount_timers[unmount_timer_count].mnt_point, MAX_PATH, mnt_point);
	unmount_timers[unmount_timer_count].timeout_ms = timeout_ms;
	unmount_timers[unmount_timer_count].start_tick = GetTickCount();
	unmount_timers[unmount_timer_count].active = TRUE;
	unmount_timer_count++;

	LeaveCriticalSection(&unmount_timer_cs);
}

void _unmount_timer_remove(const wchar_t *device)
{
	int i;
	if (!unmount_timer_inited) return;

	EnterCriticalSection(&unmount_timer_cs);

	for (i = 0; i < unmount_timer_count; i++)
	{
		if (wcscmp(unmount_timers[i].device, device) == 0)
		{
			unmount_timers[i].active = FALSE;
			memset(&unmount_timers[i], 0, sizeof(_unmount_timer_entry));

			if (i < unmount_timer_count - 1)
			{
				memmove(&unmount_timers[i], &unmount_timers[i + 1],
					(unmount_timer_count - i - 1) * sizeof(_unmount_timer_entry));
			}
			unmount_timer_count--;
			break;
		}
	}

	LeaveCriticalSection(&unmount_timer_cs);
}

void _unmount_timer_cancel_all(void)
{
	if (!unmount_timer_inited) return;

	EnterCriticalSection(&unmount_timer_cs);
	memset(unmount_timers, 0, sizeof(unmount_timers));
	unmount_timer_count = 0;
	LeaveCriticalSection(&unmount_timer_cs);
}

void _unmount_timer_purge_unmounted(void)
{
	int i;
	list_entry *node, *sub;
	BOOL found;

	if (!unmount_timer_inited) return;

	EnterCriticalSection(&unmount_timer_cs);

	i = 0;
	while (i < unmount_timer_count)
	{
		found = FALSE;

		for (node = __drives.flink; node != &__drives; node = node->flink)
		{
			_dnode *root = contain_record(node, _dnode, list);
			for (sub = root->root.vols.flink; sub != &root->root.vols; sub = sub->flink)
			{
				_dnode *mnt = contain_record(sub, _dnode, list);
				if ((mnt->mnt.info.status.flags & F_ENABLED) &&
					wcscmp(mnt->mnt.info.device, unmount_timers[i].device) == 0)
				{
					found = TRUE;
					break;
				}
			}
			if (found) break;
		}

		if (!found)
		{
			memset(&unmount_timers[i], 0, sizeof(_unmount_timer_entry));
			if (i < unmount_timer_count - 1)
			{
				memmove(&unmount_timers[i], &unmount_timers[i + 1],
					(unmount_timer_count - i - 1) * sizeof(_unmount_timer_entry));
			}
			unmount_timer_count--;
		}
		else
		{
			i++;
		}
	}

	LeaveCriticalSection(&unmount_timer_cs);
}

void _unmount_timer_check(void)
{
	int   i;
	DWORD now;
	DWORD elapsed;

	if (!unmount_timer_inited) return;

	now = GetTickCount();

	EnterCriticalSection(&unmount_timer_cs);

	i = 0;
	while (i < unmount_timer_count)
	{
		if (!unmount_timers[i].active)
		{
			memset(&unmount_timers[i], 0, sizeof(_unmount_timer_entry));
			if (i < unmount_timer_count - 1)
			{
				memmove(&unmount_timers[i], &unmount_timers[i + 1],
					(unmount_timer_count - i - 1) * sizeof(_unmount_timer_entry));
			}
			unmount_timer_count--;
			continue;
		}

		elapsed = now - unmount_timers[i].start_tick;

		if (elapsed >= unmount_timers[i].timeout_ms)
		{
			wchar_t dev[MAX_PATH];
			wcscpy_s(dev, MAX_PATH, unmount_timers[i].device);

			memset(&unmount_timers[i], 0, sizeof(_unmount_timer_entry));
			if (i < unmount_timer_count - 1)
			{
				memmove(&unmount_timers[i], &unmount_timers[i + 1],
					(unmount_timer_count - i - 1) * sizeof(_unmount_timer_entry));
			}
			unmount_timer_count--;

			LeaveCriticalSection(&unmount_timer_cs);

			dc_unmount_volume(dev, MF_FORCE);

			EnterCriticalSection(&unmount_timer_cs);
		}
		else
		{
			i++;
		}
	}

	LeaveCriticalSection(&unmount_timer_cs);
}

DWORD _unmount_timer_calc_ms(int value, int unit)
{
	if (value <= 0) return 0;

	switch (unit)
	{
	case UNMOUNT_TIMEOUT_UNIT_SEC:  return (DWORD)value * 1000;
	case UNMOUNT_TIMEOUT_UNIT_HOUR: return (DWORD)value * 3600000;
	case UNMOUNT_TIMEOUT_UNIT_MIN:
	default:                        return (DWORD)value * 60000;
	}
}

void _unmount_timer_save_defaults(int value, int unit)
{
	HKEY h_key;
	DWORD data[2];

	data[0] = (DWORD)value;
	data[1] = (DWORD)unit;

	if (RegCreateKey(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config", &h_key) == NO_ERROR)
	{
		RegSetValueEx(h_key, L"UnmountTimeout", 0, REG_BINARY,
			(const BYTE *)data, sizeof(data));
		RegCloseKey(h_key);
	}
}

void _unmount_timer_load_defaults(int *value, int *unit)
{
	HKEY  h_key;
	DWORD data[2] = { 5, UNMOUNT_TIMEOUT_UNIT_MIN };
	DWORD cb = sizeof(data);

	if (RegOpenKey(HKEY_LOCAL_MACHINE,
		L"SYSTEM\\CurrentControlSet\\Services\\dcrypt\\config", &h_key) == NO_ERROR)
	{
		if (RegQueryValueEx(h_key, L"UnmountTimeout", NULL, NULL,
			(BYTE *)data, &cb) != NO_ERROR)
		{
			data[0] = 5;
			data[1] = UNMOUNT_TIMEOUT_UNIT_MIN;
		}
		RegCloseKey(h_key);
	}
	else
	{
		data[0] = 5;
		data[1] = UNMOUNT_TIMEOUT_UNIT_MIN;
	}

	*value = (int)data[0];
	*unit  = (int)data[1];
}
