#ifndef _HOOK_FUNCTIONS_H
#define _HOOK_FUNCTIONS_H

#include "framework.h"

#include <windef.h>
#include <appmodel.h>
#include <windowsceip.h>

void WINAPI MyAcquireSRWLockExclusive(PSRWLOCK SRWLock);

void WINAPI MyAcquireSRWLockShared(PSRWLOCK SRWLock);

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

void MyAddRefActCtx(HANDLE hActCtx);

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

void MyApplicationRecoveryFinished(BOOL bSuccess);

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

BOOL WINAPI MyCancelSynchronousIo(HANDLE hThread);

void WINAPI MyCancelThreadpoolIo(PTP_IO pio);

BOOL WINAPI MyCancelWaitableTimer(HANDLE hTimer);

BOOL WINAPI MyCeipIsOptedIn();

BOOL WINAPI MyChangeTimerQueueTimer(
  HANDLE TimeerQueue, HANDLE Timer, ULONG DueTime, ULONG Period
);

BOOL WINAPI MyCheckNameLegalDOS8Dot3A(
  LPCSTR lpName,
  LPSTR lpOemName,
  DWORD OemNameSize,
  PBOOL pbNameContainsSpaces,
  PBOOL pbNameLegal
);

BOOL WINAPI MyCheckNameLegalDOS8Dot3W(
  LPCWSTR lpName,
  LPSTR lpOemName,
  DWORD OemNameSize,
  PBOOL pbNameContainsSpaces,
  PBOOL pbNameLegal
);

BOOL WINAPI MyCheckRemoteDebuggerPresent(
  HANDLE hProcess, PBOOL pbDebuggerPresent
);

BOOL WINAPI MyCheckTokenCapability(
  HANDLE TokenHandle, PSID CapabilitySidToCheck, PBOOL HasCapability
);

BOOL WINAPI MyCheckTokenMembershipEx(
  HANDLE TokenHandle, PSID SidToCheck, DWORD Flags, PBOOL IsMember
);

BOOL WINAPI MyClearCommBreak(HANDLE hFile);

BOOL WINAPI MyClearCommError(HANDLE hFile, LPDWORD lpErrors, LPCOMSTAT lpStat);

BOOL MyCloseHandle(HANDLE hObject);

LONG WINAPI MyClosePackageInfo(PACKAGE_INFO_REFERENCE packageInfoReference);

BOOLEAN WINAPI MyClosePrivateNamespace(HANDLE Handle, ULONG Flags);

void WINAPI MyClosePseudoConsole(HPCON hPC);

void WINAPI MyCloseThreadpool(PTP_POOL ptpp);

void WINAPI MyCloseThreadpoolCleanupGroup(PTP_CLEANUP_GROUP ptpcg);

void WINAPI MyCloseThreadpoolCleanupGroupMembers(
  PTP_CLEANUP_GROUP ptpcg, BOOL fCancelPendingCallbacks, PVOID pvCleanupContext
);

void WINAPI MyCloseThreadpoolIo(PTP_IO pio);

void WINAPI MyCloseThreadpoolTimer(PTP_TIMER pti);

void WINAPI MyCloseThreadpoolWait(PTP_WAIT pwa);

void WINAPI MyCloseThreadpoolWork(PTP_WORK pwk);

BOOL WINAPI MyCommConfigDialogA(LPCSTR lpszName, HWND hWnd, LPCOMMCONFIG lpCC);

BOOL WINAPI MyCommConfigDialogW(LPCWSTR lpszName, HWND hWnd, LPCOMMCONFIG lpCC);

LONG WINAPI MyCompareFileTime(
  const FILETIME* lpFileTime1, const FILETIME* lpFileTime2
);

int WINAPI MyCompareStringA(
  LCID Locale,
  DWORD dwCmpFlags,
  PCNZCH lpString1,
  int cchCount1,
  PCNZCH lpString2,
  int cchCount2
);

int WINAPI MyCompareStringEx(
  LPCWSTR lpLocaleName,
  DWORD dwCmpFlags,
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int cchCount2,
  LPNLSVERSIONINFO lpVersionInformation,
  LPVOID lpReserved,
  LPARAM lParam
);

int WINAPI MyCompareStringOrdinal(
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int cchCount2,
  BOOL bIgnoreCase
);

int WINAPI MyCompareStringW(
  LCID Locale,
  DWORD dwCmpFlags,
  _In_NLS_string_(cchCount1)PCNZWCH lpString1,
  int cchCount1,
  _In_NLS_string_(cchCount2)PCNZWCH lpString2,
  int cchCount2
);

BOOL WINAPI MyConnectNamedPipe(HANDLE hNamedPipe, LPOVERLAPPED lpOverlapped);

BOOL WINAPI MyContinueDebugEvent(
  DWORD dwProcessId, DWORD dwThreadId, DWORD dwContinueStatus
);

LCID WINAPI MyConvertDefaultLocale(LCID Locale);

BOOL WINAPI MyConvertFiberToThread();

LPVOID WINAPI MyConvertThreadToFiber(LPVOID lpParameter);

LPVOID WINAPI MyConvertThreadToFiberEx(LPVOID lpParameter, DWORD dwFlags);

BOOL WINAPI MyCopyContext(
  PCONTEXT Destination, DWORD ContextFlags, PCONTEXT Source
);

HRESULT WINAPI MyCopyFile2(
  PCWSTR pwszExistingFileName,
  PCWSTR pwszNewFileName,
  COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters
);

BOOL WINAPI MyCopyFileA(
  LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailExists
);

BOOL WINAPI MyCopyFileExA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags
);

BOOL WINAPI MyCopyFileExW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags
);

BOOL WINAPI MyCopyFileTransactedA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags,
  HANDLE hTransaction
);

BOOL WINAPI MyCopyFileTransactedW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags,
  HANDLE hTransaction
);

BOOL WINAPI MyCopyFileW(
  LPCWSTR lpExistingFileName, LPCWSTR lpNewFileName, BOOL bFailExists
);

HANDLE WINAPI MyCreateActCtxA(PCACTCTXA pActCtx);

HANDLE WINAPI MyCreateActCtxW(PCACTCTXW pActCtx);

HANDLE WINAPI MyCreateBoundaryDescriptorA(LPCSTR Name, ULONG Flags);

HANDLE WINAPI MyCreateBoundaryDescriptorW(LPCWSTR Name, ULONG Flags);

HANDLE WINAPI MyCreateConsoleScreenBuffer(
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  const SECURITY_ATTRIBUTES* lpSecurityAttributes,
  DWORD dwFlags,
  LPVOID lpScreenBuffer
);

BOOL WINAPI MyCreateDirectoryA(
  LPCSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL WINAPI MyCreateDirectoryExA(
  LPCSTR lpTempalteDirectory,
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL WINAPI MyCreateDirectoryExW(
  LPCWSTR lpTempalteDirectory,
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL WINAPI MyCreateDirectoryTransactedA(
  LPCSTR lpTempalteDirectory,
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTrancation
);

BOOL WINAPI MyCreateDirectoryTransactedW(
  LPCWSTR lpTempalteDirectory,
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTrancation
);

BOOL WINAPI MyCreateDirectoryW(
  LPCWSTR lpPathName, LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

LPVOID WINAPI MyCreateEnclave(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  SIZE_T dwInitialCommitment,
  DWORD flEnclaveType,
  LPCVOID lpEnclaveInformation,
  DWORD dwInfoLength,
  LPDWORD lpEnclaveError
);

HANDLE WINAPI MyCreateEventA(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  BOOL bManualReset,
  BOOL bInitialState,
  LPCSTR lpName
);

HANDLE WINAPI MyCreateEventExA(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateEventExW(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateEventW(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  BOOL bManualReset,
  BOOL bInitialState,
  LPCWSTR lpName
);

LPVOID WINAPI MyCreateFiber(
  SIZE_T dwStackSize, LPFIBER_START_ROUTINE lpStartAddress, LPVOID lpParameter
);

LPVOID WINAPI MyCreateFiberEx(
  SIZE_T dwStackCommitSize,
  SIZE_T dwStackReservedSize,
  DWORD dwFlags,
  LPFIBER_START_ROUTINE lpStartAddress,
  LPVOID lpParameter
);

HANDLE WINAPI MyCreateFile2(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  DWORD dwCreationDisposition,
  LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
);

HANDLE WINAPI MyCreateFileA(
  LPCSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
);

HANDLE WINAPI MyCreateFileMappingA(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCSTR lpName
);

HANDLE WINAPI MyCreateFileMappingFromApp(
  HANDLE hFile,
  PSECURITY_ATTRIBUTES SecurityAttributes,
  ULONG PageProtection,
  ULONG64 MaximumSize,
  PCWSTR Name
);

HANDLE WINAPI MyCreateFileMappingNumaA(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProject,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCSTR lpName,
  DWORD nndPreferred
);

HANDLE WINAPI MyCreateFileMappingNumaW(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProject,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName,
  DWORD nndPreferred
);

HANDLE WINAPI MyCreateFileMappingW(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName
);

HANDLE WINAPI MyCreateFileTransactedA(
  LPCSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile,
  HANDLE hTransaction,
  PUSHORT pusMiniVersion,
  PVOID lpExtendedParameter
);

HANDLE WINAPI MyCreateFileTransactedW(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile,
  HANDLE hTransaction,
  PUSHORT pusMiniVersion,
  PVOID lpExtendedParameter
);

HANDLE WINAPI MyCreateFileW(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
);

BOOL WINAPI MyCreateHardLinkA(
  LPCSTR lpFileName,
  LPCSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL WINAPI MyCreateHardLinkTransactedA(
  LPCSTR lpFileName,
  LPCSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTransaction
);

BOOL WINAPI MyCreateHardLinkTransactedW(
  LPCWSTR lpFileName,
  LPCWSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTransaction
);

BOOL WINAPI MyCreateHardLinkW(
  LPCWSTR lpFileName,
  LPCWSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI MyCreateIoCompletionPort(
  HANDLE FileHandle,
  HANDLE ExistingCompletionPort,
  ULONG_PTR CompletionKey,
  DWORD NumberOfConcurrentThreads
);

HANDLE WINAPI MyCreateJobObjectA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCSTR lpName
);

HANDLE WINAPI MyCreateJobObjectW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCWSTR lpName
);

HANDLE WINAPI MyCreateMailslotA(
  LPCSTR lpName,
  DWORD nMaxMessageSize,
  DWORD lReadTimeout,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI MyCreateMailslotW(
  LPCWSTR lpName,
  DWORD nMaxMessageSize,
  DWORD lReadTimeout,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI MyCreateMemoryResourceNotification(
  MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType
);

HANDLE WINAPI MyCreateMutexA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  BOOL bInitialOwner,
  LPCSTR lpName
);

HANDLE WINAPI MyCreateMutexExA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateMutexExW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateMutexW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  BOOL bInitialOwner,
  LPCWSTR lpName
);

HANDLE WINAPI MyCreateNamedPipeA(
  LPCSTR lpName,
  DWORD dwOpenMode,
  DWORD dwPipeMode,
  DWORD nMaxInstances,
  DWORD nOutBufferSize,
  DWORD nInBufferSize,
  DWORD nDefaultTimeOut,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

HANDLE WINAPI MyCreateNamedPipeW(
  LPCWSTR lpName,
  DWORD dwOpenMode,
  DWORD dwPipeMode,
  DWORD nMaxInstances,
  DWORD nOutBufferSize,
  DWORD nInBufferSize,
  DWORD nDefaultTimeOut,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
);

BOOL WINAPI MyCreatePipe(
  PHANDLE hReadPipe,
  PHANDLE hWritePipe,
  LPSECURITY_ATTRIBUTES lpPipeAttributes,
  DWORD nSize
);

///

HANDLE MyFindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);

HANDLE MyFindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);

BOOL MyFindNextFileA(HANDLE, LPWIN32_FIND_DATAA);

BOOL MyFindNextFileW(HANDLE, LPWIN32_FIND_DATAW);

BOOL _CheckA(LPCSTR);

BOOL _CheckW(LPCWSTR);

#endif // _HOOK_FUNCTIONS_H
