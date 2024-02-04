#ifndef _HOOK_FUNCTIONS_H
#define _HOOK_FUNCTIONS_H

#include "framework.h"
#include <appmodel.h>

VOID WINAPI MyAcquireSRWLockExclusive(PSRWLOCK SRWLock);

VOID WINAPI MyAcquireSRWLockShared(PSRWLOCK SRWLock);

BOOL WINAPI MyActivateActCtx(HANDLE hActCtx, ULONG_PTR* lpCookie);

ATOM WINAPI MyAddAtomA(LPCSTR lpString);

ATOM WINAPI MyAddAtomW(LPCWSTR lpString);

BOOL WINAPI MyAddConsoleAliasA(LPSTR Source, LPSTR Target, LPSTR ExeName);

BOOL WINAPI MyAddConsoleAliasW(LPWSTR Source, LPWSTR Target, LPWSTR ExeName);

DLL_DIRECTORY_COOKIE WINAPI MyAddDllDirectory(PCWSTR NewDirectory);

BOOL MyAddIntegrityLabelToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor, PSID IntegrityLabel
);

DWORD MyAddLocalAlternateComputerNameA(LPCSTR lpDnsFQHostName, ULONG ulFlag);

DWORD MyAddLocalAlternateComputerNameW(LPCWSTR lpDnsFQHostName, ULONG ulFlag);

VOID MyAddRefActCtx(HANDLE hActCtx);

BOOL MyAddResourceAttributeAce(
  PACL pAcl,
  DWORD dwAceRevision,
  DWORD AceFlags,
  DWORD AccessMask,
  PSID pSid,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION pAttributeInfo,
  PDWORD pReturnLength
);

BOOL MyAddSecureMemoryCacheCallback(PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack);

BOOL MyAddSIDToBoundaryDescriptor(HANDLE* BoundaryDescriptor, PSID RequireSid);

PVOID MyAddVectoredContinueHandler(
  ULONG First, PVECTORED_EXCEPTION_HANDLER Handler
);

PVOID MyAddVectoredExceptionHandler(
  ULONG First, PVECTORED_EXCEPTION_HANDLER Handler
);

BOOL MyAllocateUserPhysicalPages(
  HANDLE hProcess, PULONG_PTR NumberOfPages, PULONG_PTR PageArray
);

BOOL MyAllocateUserPhysicalPagesNuma(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray,
  DWORD nndPreferred
);

BOOL WINAPI MyAllocConsole();

VOID MyApplicationRecoveryFinished(BOOL bSuccess);

HRESULT MyApplicationRecoveryInProgress(PBOOL pbCancelled);

LONG MyAppPolicyGetClrCompat(HANDLE processToken, AppPolicyClrCompat* policy);

LONG MyAppPolicyGetMediaFoundationCodecLoading(
  HANDLE processToken, AppPolicyMediaFoundationCodecLoading* policy
);

LONG MyAppPolicyGetProcessTerminationMethod(
  HANDLE processToken, AppPolicyProcessTerminationMethod* policy
);

LONG MyAppPolicyGetThreadInitializationType(
  HANDLE processToken, AppPolicyThreadInitializationType* policy
);

LONG MyAppPolicyGetWindowingModel(
  HANDLE processToken, AppPolicyWindowingModel* policy
);

BOOL MyAreFileApisANSI();

BOOL MyAssignProcessToJobObject(HANDLE hJob, HANDLE hProcess);

BOOL WINAPI MyAttachConsole(DWORD dwProcessId);

BOOL MyBackupRead(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesRead,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
);

BOOL MyBackupSeek(
  HANDLE hFile,
  DWORD dwLowBytesToSeek,
  DWORD dwHighBytesToSeek,
  LPDWORD lpdwLowByteSeeked,
  LPDWORD lpdwHighByteSeeked,
  LPVOID* lpContext
);

BOOL MyBackupWrite(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
);

BOOL WINAPI MyBaseFlushAppcompatCache();

BOOL MyBeep(DWORD, DWORD);

HANDLE MyBeginUpdateResourceA(LPCSTR pFileName, BOOL bDeleteExistingResources);

HANDLE MyBeginUpdateResourceW(
  LPCWSTR pFileName, BOOL bDeleteExistingResources
);

BOOL MyBindIoCompletionCallback(
  HANDLE FilehHandle,
  LPOVERLAPPED_COMPLETION_ROUTINE Function,
  ULONG Flags
);

BOOL MyBuildCommDCBA(LPCSTR lpDef, LPDCB lpDCB);

BOOL MyBuildCommDCBAndTimeoutsA(
  LPCSTR lpDef, LPDCB lpDCB, LPCOMMTIMEOUTS lpCommTimeouts
);

BOOL MyBuildCommDCBAndTimeoutsW(
  LPCWSTR lpDef, LPDCB lpDCB, LPCOMMTIMEOUTS lpCommTimeouts
);

BOOL MyBuildCommDCBW(LPCWSTR lpDef, LPDCB lpDCB);

BOOL MyCallbackMayRunLong(PTP_CALLBACK_INSTANCE pci);

BOOL MyCallNamedPipeA(
  LPCSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
);

BOOL MyCallNamedPipeW(
  LPCWSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
);

BOOL WINAPI MyCancelIo(HANDLE hFile);

BOOL WINAPI MyCancelIoEx(HANDLE hFile, LPOVERLAPPED lpOverlapped);

///

BOOL MyCloseHandle(HANDLE hObject);

HANDLE MyFindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);

HANDLE MyFindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);

BOOL MyFindNextFileA(HANDLE, LPWIN32_FIND_DATAA);

BOOL MyFindNextFileW(HANDLE, LPWIN32_FIND_DATAW);

HANDLE MyCreateFileA(
  LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
);

HANDLE MyCreateFileW(
  LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE
);

BOOL _CheckA(LPCSTR);

BOOL _CheckW(LPCWSTR);

#endif // _HOOK_FUNCTIONS_H
