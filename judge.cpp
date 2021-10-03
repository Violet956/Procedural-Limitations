#include "\\JH-server\home\¾À´í³ÌÐò\cpu.h"
#include<bits\stdc++.h>
#include <TlHelp32.h>
#define ArraySize(ptr)    (sizeof(ptr) / sizeof(ptr[0]))
BOOL FindProcessPid(LPCSTR ProcessName, DWORD& dwPid);
CRITICAL_SECTION PerfDataCriticalSection;
CpuData *pPerfDataOld = NULL; /* Older perf data (saved to establish delta values) */
CpuData *pPerfData = NULL;    /* Most recent copy of perf data */
ULONG ProcessCountOld = 0;
ULONG ProcessCount = 0;
SYSTEM_BASIC_INFORMATION SystemBasicInfo;
SYSTEM_PERFORMANCE_INFORMATION SystemPerfInfo;
PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION SystemProcessorTimeInfo = NULL;
LARGE_INTEGER liOldIdleTime = { { 0, 0 } };
double dbIdleTime;
double dbKernelTime;
double dbSystemTime;
double OldKernelTime = 0;
LARGE_INTEGER liOldSystemTime = { { 0, 0 } };
long(__stdcall *NtQuerySystemInformation)(DWORD, PVOID, DWORD, DWORD *);

BOOL PerfDataInitialize(void) {
    SID_IDENTIFIER_AUTHORITY NtSidAuthority = { SECURITY_NT_AUTHORITY };
    NTSTATUS status;

    InitializeCriticalSection(&PerfDataCriticalSection);
    NtQuerySystemInformation = (long(__stdcall *)(DWORD, PVOID, DWORD, DWORD *))GetProcAddress(
        GetModuleHandle("ntdll.dll"), "NtQuerySystemInformation");

    /*
     * Get number of processors in the system
     */
    status = NtQuerySystemInformation(0, &SystemBasicInfo, sizeof(SystemBasicInfo), NULL);
    if (status != NO_ERROR)
        return FALSE;

    /*
     * Create the SYSTEM Sid
     */
    return TRUE;
}

void PerfDataUninitialize(void) { DeleteCriticalSection(&PerfDataCriticalSection); }

void GetAllProcCPUUsage() {
    ULONG ulSize;
    LONG status;
    LPBYTE pBuffer;
    ULONG BufferSize;
    PSYSTEM_PROCESS_INFORMATION pSPI;
    pCpuData pPDOld;
    ULONG Idx, Idx2;
    HANDLE hProcess;
    HANDLE hProcessToken;
    double CurrentKernelTime;
    SYSTEM_PERFORMANCE_INFORMATION SysPerfInfo;
    SYSTEM_TIMEOFDAY_INFORMATION SysTimeInfo;
    PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION SysProcessorTimeInfo;
    ULONG Buffer[64]; /* must be 4 bytes aligned! */

    /* Get new system time */
    status = NtQuerySystemInformation(3, &SysTimeInfo, sizeof(SysTimeInfo), 0);
    if (status != NO_ERROR)
        return;

    /* Get new CPU's idle time */
    status = NtQuerySystemInformation(2, &SysPerfInfo, sizeof(SysPerfInfo), NULL);
    if (status != NO_ERROR)
        return;

    /* Get processor time information */
    SysProcessorTimeInfo = (PSYSTEM_PROCESSOR_PERFORMANCE_INFORMATION)HeapAlloc(
        GetProcessHeap(), 0,
        sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * SystemBasicInfo.NumberOfProcessors);
    status = NtQuerySystemInformation(
        8, SysProcessorTimeInfo,
        sizeof(SYSTEM_PROCESSOR_PERFORMANCE_INFORMATION) * SystemBasicInfo.NumberOfProcessors, &ulSize);
    if (status != NO_ERROR)
        return;

    /* Get process information
     * We don't know how much data there is so just keep
     * increasing the buffer size until the call succeeds
     */
    BufferSize = 0;
    do {
        BufferSize += 0x10000;
        pBuffer = (LPBYTE)HeapAlloc(GetProcessHeap(), 0, BufferSize);

        status = NtQuerySystemInformation(5, pBuffer, BufferSize, &ulSize);

        if (status == STATUS_INFO_LENGTH_MISMATCH) {
            HeapFree(GetProcessHeap(), 0, pBuffer);
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH);

    EnterCriticalSection(&PerfDataCriticalSection);

    /*
     * Save system performance info
     */
    memcpy(&SystemPerfInfo, &SysPerfInfo, sizeof(SYSTEM_PERFORMANCE_INFORMATION));

    /*
     * Save system processor time info
     */
    if (SystemProcessorTimeInfo) {
        HeapFree(GetProcessHeap(), 0, SystemProcessorTimeInfo);
    }
    SystemProcessorTimeInfo = SysProcessorTimeInfo;

    /*
     * Save system handle info
     */

    for (CurrentKernelTime = 0, Idx = 0; Idx < (ULONG)SystemBasicInfo.NumberOfProcessors; Idx++) {
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].KernelTime);
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].DpcTime);
        CurrentKernelTime += Li2Double(SystemProcessorTimeInfo[Idx].InterruptTime);
    }

    /* If it's a first call - skip idle time calcs */
    if (liOldIdleTime.QuadPart != 0) {
        /*  CurrentValue = NewValue - OldValue */
        dbIdleTime = Li2Double(SysPerfInfo.IdleProcessTime) - Li2Double(liOldIdleTime);
        dbKernelTime = CurrentKernelTime - OldKernelTime;
        dbSystemTime = Li2Double(SysTimeInfo.CurrentTime) - Li2Double(liOldSystemTime);

        /*  CurrentCpuIdle = IdleTime / SystemTime */
        dbIdleTime = dbIdleTime / dbSystemTime;
        dbKernelTime = dbKernelTime / dbSystemTime;

        /*  CurrentCpuUsage% = 100 - (CurrentCpuIdle * 100) / NumberOfProcessors */
        dbIdleTime = 100.0 - dbIdleTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors;     /* + 0.5; */
        dbKernelTime = 100.0 - dbKernelTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors; /* + 0.5; */
    }

    /* Store new CPU's idle and system time */
    liOldIdleTime = SysPerfInfo.IdleProcessTime;
    liOldSystemTime = SysTimeInfo.CurrentTime;
    OldKernelTime = CurrentKernelTime;

    /* Determine the process count
     * We loop through the data we got from NtQuerySystemInformation
     * and count how many structures there are (until RelativeOffset is 0)
     */
    ProcessCountOld = ProcessCount;
    ProcessCount = 0;
    pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    while (pSPI) {
        ProcessCount++;
        if (pSPI->NextEntryOffset == 0)
            break;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSPI + pSPI->NextEntryOffset);
    }

    /* Now alloc a new PERFDATA array and fill in the data */
    if (pPerfDataOld) {
        HeapFree(GetProcessHeap(), 0, pPerfDataOld);
    }
    pPerfDataOld = pPerfData;
    pPerfData = (pCpuData)HeapAlloc(GetProcessHeap(), 0, sizeof(CpuData) * ProcessCount);
    pSPI = (PSYSTEM_PROCESS_INFORMATION)pBuffer;
    for (Idx = 0; Idx < ProcessCount; Idx++) {
        /* Get the old perf data for this process (if any) */
        /* so that we can establish delta values */
        pPDOld = NULL;
        for (Idx2 = 0; Idx2 < ProcessCountOld; Idx2++) {
            if (pPerfDataOld[Idx2].dwPID == pSPI->UniqueProcessId) {
                pPDOld = &pPerfDataOld[Idx2];
                break;
            }
        }

        /* Clear out process perf data structure */
        memset(&pPerfData[Idx], 0, sizeof(CpuData));

        pPerfData[Idx].dwPID = pSPI->UniqueProcessId;

        if (pPDOld) {
            double CurTime = Li2Double(pSPI->KernelTime) + Li2Double(pSPI->UserTime);
            double OldTime = Li2Double(pPDOld->KernelTime) + Li2Double(pPDOld->UserTime);
            double CpuTime = (CurTime - OldTime) / dbSystemTime;
            CpuTime = CpuTime * 100.0 / (double)SystemBasicInfo.NumberOfProcessors; /* + 0.5; */
            pPerfData[Idx].cpuusage = (ULONG)CpuTime;
        }
        pPerfData[Idx].cputime.QuadPart = pSPI->UserTime.QuadPart + pSPI->KernelTime.QuadPart;

        if (pSPI->UniqueProcessId != NULL) {
            hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | READ_CONTROL, FALSE,
                                   PtrToUlong(pSPI->UniqueProcessId));
            if (hProcess) {
                /* don't query the information of the system process. It's possible but
                   returns Administrators as the owner of the process instead of SYSTEM */
                if (pSPI->UniqueProcessId != 0x4) {
                    if (OpenProcessToken(hProcess, TOKEN_QUERY, &hProcessToken)) {
                        DWORD RetLen = 0;
                        BOOL Ret;

                        Ret = GetTokenInformation(hProcessToken, TokenUser, (LPVOID)Buffer, sizeof(Buffer),
                                                  &RetLen);
                        CloseHandle(hProcessToken);
                    }
                }

                CloseHandle(hProcess);
            }
        }
        pPerfData[Idx].UserTime.QuadPart = pSPI->UserTime.QuadPart;
        pPerfData[Idx].KernelTime.QuadPart = pSPI->KernelTime.QuadPart;
        pSPI = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)pSPI + pSPI->NextEntryOffset);
    }
    HeapFree(GetProcessHeap(), 0, pBuffer);
    LeaveCriticalSection(&PerfDataCriticalSection);
}

int PerfGetIndexByProcessId(DWORD dwProcessId) {
    int Index, FoundIndex = -1;

    EnterCriticalSection(&PerfDataCriticalSection);

    for (Index = 0; Index < (int)ProcessCount; Index++) {
        if ((DWORD)pPerfData[Index].dwPID == dwProcessId) {
            FoundIndex = Index;
            break;
        }
    }

    LeaveCriticalSection(&PerfDataCriticalSection);

    return FoundIndex;
}

ULONG PerfDataGetCPUUsage(DWORD dwProcessId) {
    ULONG CpuUsage;
    int Index, FoundIndex = -1;

    EnterCriticalSection(&PerfDataCriticalSection);

    for (Index = 0; Index < (int)ProcessCount; Index++) {
        if ((DWORD)pPerfData[Index].dwPID == dwProcessId) {
            FoundIndex = Index;
            break;
        }
    }

    if (Index < (int)ProcessCount)
        CpuUsage = pPerfData[Index].cpuusage;
    else
        CpuUsage = 0;

    LeaveCriticalSection(&PerfDataCriticalSection);

    return CpuUsage;
}

int main(void) {
	LPCSTR ListApps[]{
        "Connect-SAXI-SERVER.exe"
    };
    // StopMyService();
    DWORD dwPid = 0;
    PerfDataInitialize();
    int kkksc03=0;
    int PID_CX;
    if (FindProcessPid(ListApps[0], dwPid))
    {
        printf("[%s] [%d]\n", ListApps[0], dwPid);
        PID_CX=dwPid;
    }
    else
    {
        printf("[%s] [Not Found]\n", ListApps[0]);
        return 0;
    }
    while (1) {
        GetAllProcCPUUsage();
        int CPU_zhanyong=PerfDataGetCPUUsage(PID_CX);
        if(CPU_zhanyong>=90)
        {
        	if(kkksc03>=20)
        	{
        		system("taskkill /f /t /im Connect-SAXI-SERVER.exe");
        		system("C:\\Connect-SAXI-SERVER.exe");
        		
        		FindProcessPid(ListApps[0], dwPid);
        		PID_CX=dwPid;
        		kkksc03=0;
			}
        	kkksc03++;
		}
        printf("PID:%d   CPU:%u \n\n", PID_CX,CPU_zhanyong);
        Sleep(1000);
    }
    return 0;
}

BOOL FindProcessPid(LPCSTR ProcessName, DWORD& dwPid)
{
    HANDLE hProcessSnap;
    PROCESSENTRY32 pe32;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return(FALSE);
    }

    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hProcessSnap, &pe32))
    {
        CloseHandle(hProcessSnap);          // clean the snapshot object
        return(FALSE);
    }

    BOOL    bRet = FALSE;
    do
    {
        if (!strcmp(ProcessName, pe32.szExeFile))
        {
            dwPid = pe32.th32ProcessID;
            bRet = TRUE;
            break;
        }

    } while (Process32Next(hProcessSnap, &pe32));

    CloseHandle(hProcessSnap);
    return bRet;
}
