/*
    *
    * DiskCryptor - open source partition encryption tool
    * Copyright (c) 2026
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

#include <windows.h>
#include <process.h>
#include <tlhelp32.h>
#include <shlwapi.h>
#include <bcrypt.h>

#include "main.h"
#include "secure_desktop.h"
#include "dcconst.h"

#pragma comment(lib, "bcrypt.lib")

/* Monitor period for desktop switching (ms) */
#define SECURE_DESKTOP_MONITOR_PERIOD  500

/* Critical section for secure desktop operations */
static CRITICAL_SECTION cs_secure_desktop;

/* Global state for secure desktop */
static volatile BOOL g_secure_desktop_ongoing = FALSE;
static wchar_t g_secure_desktop_name[65] = { 0 };

/* Parameters passed to secure desktop thread */
typedef struct _secure_desktop_thread_param {
    HDESK       hDesk;
    LPCWSTR     szDesktopName;
    HINSTANCE   hInstance;
    LPCWSTR     lpTemplateName;
    DLGPROC     lpDialogFunc;
    LPARAM      dwInitParam;
    INT_PTR     retValue;
    BOOL        bDlgDisplayed;
} secure_desktop_thread_param;

/* Parameters for desktop monitoring thread */
typedef struct _secure_desktop_monitor_param {
    LPCWSTR szDesktopName;
    HDESK   hDesktop;
    HANDLE  hStopEvent;
} secure_desktop_monitor_param;

void secure_desktop_init(void)
{
    InitializeCriticalSection(&cs_secure_desktop);
}

void secure_desktop_cleanup(void)
{
    DeleteCriticalSection(&cs_secure_desktop);
}

BOOL is_secure_desktop_active(void)
{
    return g_secure_desktop_ongoing;
}

BOOL is_thread_in_secure_desktop(DWORD dwThreadID)
{
    BOOL bRet = FALSE;

    if (g_secure_desktop_ongoing)
    {
        HDESK currentDesk = GetThreadDesktop(dwThreadID);
        if (currentDesk)
        {
            LPWSTR szName = NULL;
            DWORD dwLen = 0;

            if (!GetUserObjectInformationW(currentDesk, UOI_NAME, NULL, 0, &dwLen))
            {
                szName = (LPWSTR)malloc(dwLen);
                if (szName)
                {
                    if (GetUserObjectInformationW(currentDesk, UOI_NAME, szName, dwLen, &dwLen))
                    {
                        if (_wcsicmp(szName, g_secure_desktop_name) == 0)
                            bRet = TRUE;
                    }
                    free(szName);
                }
            }
        }
    }

    return bRet;
}

/*
 * Generate a random desktop name using BCryptGenRandom
 */
static BOOL generate_random_desktop_name(wchar_t *name, size_t name_len)
{
    unsigned char random_bytes[32];
    size_t i;
    NTSTATUS status;

    if (name_len < 65)
        return FALSE;

    /* Get random bytes from Windows CSPRNG */
    status = BCryptGenRandom(NULL, random_bytes, sizeof(random_bytes),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        return FALSE;

    /* Convert to hex string */
    for (i = 0; i < sizeof(random_bytes); i++)
    {
        _snwprintf(name + (i * 2), 3, L"%02X", random_bytes[i]);
    }
    name[64] = L'\0';

    /* Wipe random bytes */
    SecureZeroMemory(random_bytes, sizeof(random_bytes));

    return TRUE;
}

/*
 * Monitor thread to ensure our secure desktop stays active.
 * This prevents other processes from stealing focus.
 */
static unsigned int __stdcall secure_desktop_monitor_thread(LPVOID lpThreadParameter)
{
    secure_desktop_monitor_param *pParam = (secure_desktop_monitor_param *)lpThreadParameter;

    if (pParam)
    {
        HANDLE hStopEvent = pParam->hStopEvent;
        LPCWSTR szDesktopName = pParam->szDesktopName;
        HDESK hDesktop = pParam->hDesktop;

        /* Loop until stop event is signaled */
        while (WaitForSingleObject(hStopEvent, SECURE_DESKTOP_MONITOR_PERIOD) == WAIT_TIMEOUT)
        {
            BOOL bPerformSwitch = FALSE;
            HDESK currentDesk = OpenInputDesktop(0, FALSE, GENERIC_READ);

            if (currentDesk)
            {
                LPWSTR szName = NULL;
                DWORD dwLen = 0;

                if (!GetUserObjectInformationW(currentDesk, UOI_NAME, NULL, 0, &dwLen))
                {
                    szName = (LPWSTR)malloc(dwLen);
                    if (szName)
                    {
                        if (GetUserObjectInformationW(currentDesk, UOI_NAME, szName, dwLen, &dwLen))
                        {
                            /* Switch if we're on the default desktop or another desktop */
                            if (_wcsicmp(szName, L"Default") == 0)
                                bPerformSwitch = TRUE;
                            else if (_wcsicmp(szName, szDesktopName) != 0)
                                bPerformSwitch = TRUE;
                        }
                        free(szName);
                    }
                }
                CloseDesktop(currentDesk);
            }

            if (bPerformSwitch)
                SwitchDesktop(hDesktop);
        }
    }

    return 0;
}

/*
 * Main secure desktop thread - creates desktop and displays dialog
 */
static unsigned int __stdcall secure_desktop_thread(LPVOID lpThreadParameter)
{
#ifndef _DEBUG
    HANDLE hMonitorThread = NULL;
    unsigned int monitorThreadID = 0;
    secure_desktop_monitor_param monitorParam;
#endif
    secure_desktop_thread_param *pParam = (secure_desktop_thread_param *)lpThreadParameter;
    BOOL bNewDesktopSet = FALSE;
    HDESK hSecureDesk;
    DWORD desktopAccess = DESKTOP_CREATEMENU | DESKTOP_CREATEWINDOW |
                          DESKTOP_READOBJECTS | DESKTOP_SWITCHDESKTOP | DESKTOP_WRITEOBJECTS;

    /* Create new desktop */
    hSecureDesk = CreateDesktopW(pParam->szDesktopName, NULL, NULL, 0, desktopAccess, NULL);
    if (!hSecureDesk)
    {
        return 0;
    }

    /* Store desktop name for is_thread_in_secure_desktop() */
    wcsncpy(g_secure_desktop_name, pParam->szDesktopName, 64);
    g_secure_desktop_name[64] = L'\0';
    pParam->hDesk = hSecureDesk;

    /* Set this thread to use the secure desktop */
    bNewDesktopSet = SetThreadDesktop(hSecureDesk);

    if (bNewDesktopSet)
    {
        HMODULE hImmDll = NULL;
#ifndef _DEBUG
        HANDLE hStopEvent = NULL;
#endif

        /* Disable IME to prevent potential security issues */
        hImmDll = LoadLibraryExW(L"imm32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
        if (hImmDll)
        {
            typedef BOOL (WINAPI *ImmDisableIME_t)(DWORD);
            ImmDisableIME_t pfnImmDisableIME = (ImmDisableIME_t)GetProcAddress(hImmDll, "ImmDisableIME");
            if (pfnImmDisableIME)
            {
                pfnImmDisableIME(0);
            }
        }

        /* Wait for SwitchDesktop to succeed */
        while (TRUE)
        {
            if (SwitchDesktop(hSecureDesk))
                break;
            Sleep(SECURE_DESKTOP_MONITOR_PERIOD);
        }

        /* Create monitoring thread to keep our desktop active */
        /* Disabled in debug builds to allow switching away for debugging */
#ifndef _DEBUG
        hStopEvent = CreateEventW(NULL, TRUE, FALSE, NULL);
        if (hStopEvent)
        {
            monitorParam.szDesktopName = pParam->szDesktopName;
            monitorParam.hDesktop = hSecureDesk;
            monitorParam.hStopEvent = hStopEvent;
            hMonitorThread = (HANDLE)_beginthreadex(NULL, 0, secure_desktop_monitor_thread,
                                                     (LPVOID)&monitorParam, 0, &monitorThreadID);
        }
#endif

        /* Display the dialog on the secure desktop */
        pParam->retValue = DialogBoxParamW(pParam->hInstance, pParam->lpTemplateName,
                                           NULL, pParam->lpDialogFunc, pParam->dwInitParam);

        /* Stop monitoring thread */
#ifndef _DEBUG
        if (hMonitorThread)
        {
            SetEvent(hStopEvent);
            WaitForSingleObject(hMonitorThread, INFINITE);
            CloseHandle(hMonitorThread);
        }

        if (hStopEvent)
            CloseHandle(hStopEvent);
#endif

        pParam->bDlgDisplayed = TRUE;

        /* Cleanup IME DLL */
        if (hImmDll)
            FreeLibrary(hImmDll);
    }
    else
    {
        pParam->bDlgDisplayed = FALSE;
    }

    return 0;
}

/*
 * Get list of ctfmon.exe process IDs (for cleanup after desktop destruction)
 */
static void get_ctfmon_process_list(DWORD *pidList, int *count, int maxCount)
{
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pEntry;

    *count = 0;

    if (hSnapshot == INVALID_HANDLE_VALUE)
        return;

    pEntry.dwSize = sizeof(pEntry);

    if (Process32FirstW(hSnapshot, &pEntry))
    {
        do
        {
            LPCWSTR szFileName = PathFindFileNameW(pEntry.szExeFile);
            if (_wcsicmp(szFileName, L"ctfmon.exe") == 0)
            {
                if (*count < maxCount)
                {
                    pidList[(*count)++] = pEntry.th32ProcessID;
                }
            }
        } while (Process32NextW(hSnapshot, &pEntry));
    }

    CloseHandle(hSnapshot);
}

/*
 * Kill a process by ID
 */
static void kill_process(DWORD dwProcessId)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, dwProcessId);
    if (hProcess != NULL)
    {
        TerminateProcess(hProcess, (UINT)-1);
        CloseHandle(hProcess);
    }
}

/*
 * Check if a PID is in the given list
 */
static BOOL pid_in_list(DWORD pid, DWORD *list, int count)
{
    int i;
    for (i = 0; i < count; i++)
    {
        if (list[i] == pid)
            return TRUE;
    }
    return FALSE;
}

INT_PTR secure_desktop_dialog_box_param(
    HINSTANCE hInstance,
    LPCWSTR lpTemplateName,
    HWND hWndParent,
    DLGPROC lpDialogFunc,
    LPARAM dwInitParam)
{
    wchar_t szDesktopName[65] = { 0 };
    BOOL bSuccess = FALSE;
    INT_PTR retValue = 0;

    /* Check if secure desktop is enabled in config */
    if ((__config.conf_flags & CONF_SECURE_DESKTOP) &&
        !is_thread_in_secure_desktop(GetCurrentThreadId()))
    {
        BOOL bRandomNameGenerated = FALSE;
        HDESK existedDesk = NULL;

        EnterCriticalSection(&cs_secure_desktop);
        g_secure_desktop_ongoing = TRUE;

        /* Generate unique desktop name */
        do
        {
            if (existedDesk)
            {
                CloseDesktop(existedDesk);
                existedDesk = NULL;
            }

            if (generate_random_desktop_name(szDesktopName, 65))
            {
                existedDesk = OpenDesktopW(szDesktopName, 0, FALSE, GENERIC_READ);
                if (!existedDesk)
                {
                    bRandomNameGenerated = TRUE;
                }
            }
        } while (existedDesk);

        if (bRandomNameGenerated)
        {
            DWORD ctfmonBefore[64], ctfmonAfter[64];
            int ctfmonBeforeCount = 0, ctfmonAfterCount = 0;
            HDESK hOriginalDesk = NULL;
            secure_desktop_thread_param param;

            /* Wait for input desktop to be available */
            while (!(hOriginalDesk = OpenInputDesktop(0, TRUE, GENERIC_ALL)))
            {
                Sleep(SECURE_DESKTOP_MONITOR_PERIOD);
            }

            /* Get initial ctfmon.exe list */
            get_ctfmon_process_list(ctfmonBefore, &ctfmonBeforeCount, 64);

            /* Setup parameters for secure desktop thread */
            param.hDesk = NULL;
            param.szDesktopName = szDesktopName;
            param.hInstance = hInstance;
            param.lpTemplateName = lpTemplateName;
            param.lpDialogFunc = lpDialogFunc;
            param.dwInitParam = dwInitParam;
            param.retValue = 0;
            param.bDlgDisplayed = FALSE;

            /* Create and run the secure desktop thread */
            {
                HANDLE hThread = (HANDLE)_beginthreadex(NULL, 0, secure_desktop_thread,
                                                        (LPVOID)&param, 0, NULL);
                if (hThread)
                {
                    WaitForSingleObject(hThread, INFINITE);
                    CloseHandle(hThread);

                    if (param.bDlgDisplayed)
                    {
                        retValue = param.retValue;
                        bSuccess = TRUE;

                        /* Switch back to original desktop */
                        while (!SwitchDesktop(hOriginalDesk))
                        {
                            Sleep(SECURE_DESKTOP_MONITOR_PERIOD);
                        }

                        SetThreadDesktop(hOriginalDesk);

                        /* Allow desktop to fully settle before returning */
                        {
                            MSG msg;
                            /* Small delay to let desktop initialize */
                            Sleep(50);
                            /* Pump any pending messages to settle window state */
                            while (PeekMessage(&msg, NULL, 0, 0, PM_REMOVE))
                            {
                                TranslateMessage(&msg);
                                DispatchMessage(&msg);
                            }
                            /* Bring parent window to foreground if valid */
                            if (hWndParent && IsWindow(hWndParent))
                            {
                                SetForegroundWindow(hWndParent);
                            }
                        }
                    }

                    if (param.hDesk)
                    {
                        CloseDesktop(param.hDesk);
                    }
                }
            }

            /* Kill any ctfmon.exe instances created for our desktop */
            get_ctfmon_process_list(ctfmonAfter, &ctfmonAfterCount, 64);
            {
                int i;
                for (i = 0; i < ctfmonAfterCount; i++)
                {
                    if (!pid_in_list(ctfmonAfter[i], ctfmonBefore, ctfmonBeforeCount))
                    {
                        kill_process(ctfmonAfter[i]);
                    }
                }
            }

            CloseDesktop(hOriginalDesk);
            SecureZeroMemory(szDesktopName, sizeof(szDesktopName));
        }

        g_secure_desktop_ongoing = FALSE;
        LeaveCriticalSection(&cs_secure_desktop);
    }

    /* Fallback to normal dialog if secure desktop failed or is disabled */
    if (!bSuccess)
    {
        retValue = DialogBoxParamW(hInstance, lpTemplateName, hWndParent,
                                   lpDialogFunc, dwInitParam);
    }

    return retValue;
}
