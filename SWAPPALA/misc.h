#pragma once

#include <Windows.h>


SIZE_T RetrieveModuleSize(PBYTE sacDllBase) {

    PIMAGE_DOS_HEADER pImgDosHdrSacDll = NULL;
    PIMAGE_NT_HEADERS pImgNTHdrSacDll = NULL;

    //MB(NULL, msg, msg, MB_OK | MB_ICONINFORMATION);
    if (sacDllBase == NULL) {
        return FALSE;
    }

    pImgDosHdrSacDll = (PIMAGE_DOS_HEADER)sacDllBase;
    if (pImgDosHdrSacDll->e_magic != IMAGE_DOS_SIGNATURE) {

        return NULL;
    }

    pImgNTHdrSacDll = (PIMAGE_NT_HEADERS)(sacDllBase + pImgDosHdrSacDll->e_lfanew);
    if (pImgNTHdrSacDll->Signature != IMAGE_NT_SIGNATURE)
        return NULL;

    
    return (SIZE_T)pImgNTHdrSacDll->OptionalHeader.SizeOfImage;

}

size_t custom_strlen(char str[]) {


    size_t len = 0;
    while (str[len] != '\0') {
        len++;
    }
    return len++;
}

size_t custom_wcslen(const wchar_t* str) {
    if (!str)
        return 0;

    size_t len = 0;

    while (str[len] != L'\0') {
        len++;
    }

    return len++;
}

BOOL CompareNStringWIDE(WCHAR str1[], WCHAR str2[], int n) {


    int i = 0;
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

BOOL CompareNStringASCII(CHAR str1[], CHAR str2[], int n) {


    int i = 0;
    while (str1[i] && str2[i] && i < n) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

BOOL CompareStringASCII(CHAR str1[], CHAR str2[]) {

    if (custom_strlen(str1) != custom_strlen(str2)) {
        return FALSE;
    }

    int i = 0;
    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    // Check if both strings have reached the null terminator at the same time
    return TRUE;
}

BOOL containsSubstringUnicode(PWSTR str, WCHAR substring[], int strLen, int subLen) {


    CHAR dest[100] = { 0 };

    if (subLen > strLen)
        return FALSE;

    for (size_t i = 0; i <= (strLen - subLen + 1); ++i) {

        for (int j = 0; j < subLen; j++) {

            if (str[i + j] != substring[j]) {

                break;
            }

            if (j == (subLen - 1)) {

                return TRUE;

            }

        }
    }

    return FALSE;
}

BOOL CompareStringWIDE(WCHAR str1[], WCHAR str2[]) {

    int i = 0;

    while (str1[i] && str2[i]) {

        if (str1[i] != str2[i]) {
            return FALSE; // Characters don't match, strings are different
        }
        i++;
    }

    return TRUE;
}