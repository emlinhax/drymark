#include <windows.h>
#include <Shlwapi.h>
#include <tlhelp32.h>
#include <iostream>

typedef unsigned long long u64;

typedef NTSTATUS(NTAPI* pNtQueryInformationThread)(HANDLE ThreadHandle, unsigned int ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

// CImmersiveWatermark::_LaunchKernelThread | first if-check (we patch it to always fail)
BYTE pattern[] = { 0x0F, 0x85 ,0x83 ,0x00 ,0x00 ,0x00 ,0x48 ,0x21 ,0x5C };
const char* mask = "xxxxxxxxx";

u64 pattern_scan(u64 start, size_t range, BYTE pattern[], const char* mask)
{
    int patternLength = (DWORD)strlen(mask);

    for (u64 i = 0; i < range - patternLength; ++i)
    {
        bool found = true;
        for (int j = 0; j < patternLength; ++j)
        {
            if (mask[j] != '?' && ((BYTE*)start)[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }

        if (found)
        {
            return start + i;
        }
    }

    return 0;
}

HANDLE find_watermark_thread() {
    HMODULE ntdll = LoadLibraryA("ntdll.dll");
    pNtQueryInformationThread NtQueryInformationThread = (pNtQueryInformationThread)GetProcAddress(ntdll, "NtQueryInformationThread");
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    THREADENTRY32 te = { sizeof(THREADENTRY32) };

    for (BOOL hasNext = Thread32First(hSnapshot, &te); hasNext; hasNext = Thread32Next(hSnapshot, &te)) {
        if (te.th32OwnerProcessID == GetCurrentProcessId()) {
            HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            u64 pEntryPoint = 0;
            if (NtQueryInformationThread(hThread, 0x09, &pEntryPoint, sizeof(pEntryPoint), nullptr) == 0) {
                //CImmersiveWatermark___OnDisplayChange + 0x16
                //push r15
                //41 57 opcode
                if (pEntryPoint != 0 && 
                    *(char*)(pEntryPoint + 0x16) == 0x41)
                {
                    CloseHandle(hSnapshot);
                    return hThread;
                }
            }
            CloseHandle(hThread);
        }
    }

    CloseHandle(hSnapshot);
    return 0;
}

bool patch_kmthreadstarter()
{
    u64 pExplorer = (u64)GetModuleHandleA(NULL);

    u64 pCImmersiveWatermark___LaunchKernelThread = pattern_scan(pExplorer, 0x200000, pattern, mask);
    if (!pCImmersiveWatermark___LaunchKernelThread)
        return false;

    DWORD v0;
    VirtualProtect((void*)pCImmersiveWatermark___LaunchKernelThread, 6, PAGE_EXECUTE_READWRITE, &v0);
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x0) = 0xE9; // jmp
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x1) = 0x84; // offset
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x2) = 0x00; // ...
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x3) = 0x00; // ...
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x4) = 0x00; // ...
    *(char*)(pCImmersiveWatermark___LaunchKernelThread + 0x5) = 0x90; // nop
    VirtualProtect((void*)pCImmersiveWatermark___LaunchKernelThread, 6, v0, &v0);

    return true;
}

void main()
{
    bool status = patch_kmthreadstarter();
    if (!status)
        return;

    Beep(500, 100);
    Sleep(500);

    HANDLE hWatermarkThread = find_watermark_thread();
    if (hWatermarkThread != 0)
    {
        TerminateThread(hWatermarkThread, 0);
        Beep(1000, 100);
    }
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD  ul_reason_for_call, LPVOID lpReserved)
{
    if (ul_reason_for_call == DLL_PROCESS_ATTACH)
    {
        main();
    }
    return TRUE;
}

