#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <stdio.h>
#include <winternl.h>
#include <tchar.h>
#include <ntstatus.h>

#pragma comment(lib, "ntdll.lib")
#define ProcessBreakawayMode                  (PROCESS_INFORMATION_CLASS)29
#define PROCESS_BREAKAWAY_MASK                (DWORD)0x07000000L 

typedef NTSTATUS(WINAPI* pNtSetInformationProcess)(HANDLE, PROCESS_INFORMATION_CLASS, PVOID, ULONG);

bool IsCriticalProcess(HANDLE hProcess) {
    NTSTATUS status;
    ULONG BreakOnTermination;
    status = NtQueryInformationProcess(hProcess, ProcessBreakOnTermination, &BreakOnTermination, sizeof(BreakOnTermination), NULL);
    if (NT_SUCCESS(status)) {
        if (BreakOnTermination == 1) {
            return true;
        }
    }
    return false;
}

bool SetPrivilege(HANDLE hToken, LPCTSTR Privilege, BOOL bEnablePrivilege) {
    TOKEN_PRIVILEGES tp = { 0 };
    LUID luid;

    if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
        return false;
    }

    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = (bEnablePrivilege) ? SE_PRIVILEGE_ENABLED : 0;

    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL)) {
        return false;
    }

    return (GetLastError() == ERROR_SUCCESS);
}

int main(int argc, char** argv)
{
    printf_s("Hello World!\n");

    if (argc < 2)
    {
        system("tasklist && pause");
        MessageBox(NULL, L"No process ID specified, Usage : <ToolName.exe> <process_id>", L"Error", MB_ICONERROR);
        return 1;
    }

    DWORD processId = atoi(argv[1]);
    if (processId == 0)
    {
        MessageBox(NULL, L"Invalid process ID", L"Error", MB_ICONERROR);
        return 1;
    }

    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_SET_INFORMATION, FALSE, processId);
    if (hProcess == NULL) {
        MessageBox(NULL, L"Failed to open process", L"Error", MB_ICONERROR);
        return 1;
    }

    bool isCritical = IsCriticalProcess(hProcess);

    if (isCritical) {
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
            if (SetPrivilege(hToken, SE_DEBUG_NAME, TRUE)) {
                pNtSetInformationProcess NtSetInformationProcess = (pNtSetInformationProcess)GetProcAddress(GetModuleHandle(L"ntdll.dll"), "NtSetInformationProcess");
                if (NtSetInformationProcess != NULL) {
                    ULONG BreakawayFlags = 0;
                    if (NtSetInformationProcess(hProcess, ProcessBreakawayMode, &BreakawayFlags, sizeof(BreakawayFlags)) == STATUS_SUCCESS) {
                        MessageBox(NULL, L"Removed critical system process property", L"Success", MB_ICONINFORMATION);
                        TerminateProcess(hProcess, 0);
                    }
                    else {
                        MessageBox(NULL, L"Failed to remove critical system process property", L"Error", MB_ICONERROR);
                    }
                }
                else {
                    MessageBox(NULL, L"Failed to get address of NtSetInformationProcess function", L"Error", MB_ICONERROR);
                }
            }
            else {
                MessageBox(NULL, L"Failed to enable SE_DEBUG_NAME privilege", L"Error", MB_ICONERROR);
            }
        }
        else {
            MessageBox(NULL, L"Failed to open process token", L"Error", MB_ICONERROR);
        }

        CloseHandle(hProcess);
    }
    else {
        MessageBox(NULL, L"Process is not a critical system process", L"Error", MB_ICONERROR);
        TerminateProcess(hProcess, 0);
        CloseHandle(hProcess);
    }

    return 0;
}