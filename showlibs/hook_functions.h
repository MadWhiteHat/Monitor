#ifndef _HOOK_FUNCTIONS_H
#define _HOOK_FUNCTIONS_H

#include "framework.h"
#include <appmodel.h>

void _MyAcquireSRWLockExclusive(PSRWLOCK);
void _MyAcquireSRWLockShared(PSRWLOCK);
BOOL _MyActivateActCtx(HANDLE, ULONG_PTR*);
ATOM _MyAddAtomA(LPCSTR);
ATOM _MyAddAtomW(LPCWSTR);
BOOL WINAPI _MyAddConsoleAliasA(LPCSTR, LPCSTR, LPCSTR);
BOOL WINAPI _MyAddConsoleAliasW(LPCWSTR, LPCWSTR, LPCWSTR);
DLL_DIRECTORY_COOKIE _MyAddDllDirectory(PCWSTR);
BOOL _MyAddIntegrityLabelToBoundaryDescriptor(HANDLE*, PSID);
DWORD _MyAddLocalAlternateComputerNameA(LPCSTR, ULONG);
DWORD _MyAddLocalAlternateComputerNameW(LPCWSTR, ULONG);
void _MyAddRefActCtx(HANDLE);
BOOL _MyAddResourceAttributeAce(PACL, DWORD, DWORD, DWORD, PSID,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION, PDWORD);
BOOL _MyAddSecureMemoryCacheCallback(PSECURE_MEMORY_CACHE_CALLBACK);
BOOL _MyAddSIDToBoundaryDescriptor(HANDLE*, PSID);
PVOID _MyAddVectoredContinueHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
PVOID _MyAddVectoredExceptionHandler(ULONG, PVECTORED_EXCEPTION_HANDLER);
BOOL _MyAllocateUserPhysicalPages(HANDLE, PULONG_PTR, PULONG_PTR);
BOOL _MyAllocateUserPhysicalPagesNuma(HANDLE, PULONG_PTR, PULONG_PTR, DWORD);
BOOL WINAPI _MyAllocConsole();
void _MyApplicationRecoveryFinished(BOOL);
HRESULT _MyApplicationRecoveryInProgress(PBOOL);
LONG _MyAppPolicyGetClrCompat(HANDLE, AppPolicyClrCompat*);
LONG _MyAppPolicyGetMediaFoundationCodecLoading(HANDLE,
  AppPolicyMediaFoundationCodecLoading*);
LONG _MyAppPolicyGetProcessTerminationMethod(HANDLE,
  AppPolicyProcessTerminationMethod*);
LONG _MyAppPolicyGetThreadInitializationType(HANDLE,
  AppPolicyThreadInitializationType*);
LONG _MyAppPolicyGetWindowingModel(HANDLE, AppPolicyWindowingModel*);
BOOL _MyAreFileApisANSI();
BOOL _MyAssignProcessToJobObject(HANDLE, HANDLE);
BOOL WINAPI _MyAttachConsole(DWORD);
BOOL _MyBackupRead(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID*);
BOOL _MyBackupSeek(HANDLE, DWORD, DWORD, LPDWORD, LPDWORD, LPVOID*);
BOOL _MyBackupWrite(HANDLE, LPBYTE, DWORD, LPDWORD, BOOL, BOOL, LPVOID*);

HANDLE _MyFindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);
HANDLE _MyFindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);

BOOL _MyFindNextFileA(HANDLE, LPWIN32_FIND_DATAA);
BOOL _MyFindNextFileW(HANDLE, LPWIN32_FIND_DATAW);

HANDLE _MyCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
HANDLE _MyCreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);

BOOL _MyBeep(DWORD, DWORD);

BOOL _CheckA(LPCSTR);
BOOL _CheckW(LPCWSTR);

#endif // _HOOK_FUNCTIONS_H
