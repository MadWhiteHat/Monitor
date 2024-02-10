#ifndef _HOOK_FUNCTIONS_H
#define _HOOK_FUNCTIONS_H

#include "framework.h"

#include <windef.h>
#include <appmodel.h>

void WINAPI MyAcquireSRWLockExclusive(
  PSRWLOCK SRWLock
);

void WINAPI MyAcquireSRWLockShared(
  PSRWLOCK SRWLock
);

BOOL WINAPI MyActivateActCtx(
  HANDLE hActCtx,
  ULONG_PTR* lpCookie
);

ATOM WINAPI MyAddAtomA(
  LPCSTR lpString
);

ATOM WINAPI MyAddAtomW(
  LPCWSTR lpString
);

BOOL WINAPI MyAddConsoleAliasA(
  LPSTR Source,
  LPSTR Target,
  LPSTR ExeName
);

BOOL WINAPI MyAddConsoleAliasW(
  LPWSTR Source,
  LPWSTR Target,
  LPWSTR ExeName
);

DLL_DIRECTORY_COOKIE WINAPI MyAddDllDirectory(
  PCWSTR NewDirectory
);

BOOL WINAPI MyAddIntegrityLabelToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor,
  PSID IntegrityLabel
);

void WINAPI MyAddRefActCtx(
  HANDLE hActCtx
);

BOOL WINAPI MyAddResourceAttributeAce(
  PACL pAcl,
  DWORD dwAceRevision,
  DWORD AceFlags,
  DWORD AccessMask,
  PSID pSid,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION pAttributeInfo,
  PDWORD pReturnLength
);

BOOL WINAPI MyAddSecureMemoryCacheCallback(
  PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack
);

BOOL WINAPI MyAddSIDToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor,
  PSID RequireSid
);

PVOID WINAPI MyAddVectoredContinueHandler(
  ULONG First,
  PVECTORED_EXCEPTION_HANDLER Handler
);

PVOID WINAPI MyAddVectoredExceptionHandler(
  ULONG First,
  PVECTORED_EXCEPTION_HANDLER Handler
);

BOOL WINAPI MyAllocateUserPhysicalPages(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray
);

BOOL WINAPI MyAllocateUserPhysicalPagesNuma(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray,
  DWORD nndPreferred
);

BOOL WINAPI MyAllocConsole();

void WINAPI MyApplicationRecoveryFinished(
  BOOL bSuccess
);

HRESULT WINAPI MyApplicationRecoveryInProgress(
  PBOOL pbCancelled
);

LONG WINAPI MyAppPolicyGetClrCompat(
  HANDLE processToken,
  AppPolicyClrCompat* policy
);

LONG WINAPI MyAppPolicyGetMediaFoundationCodecLoading(
  HANDLE processToken,
  AppPolicyMediaFoundationCodecLoading* policy
);

LONG WINAPI MyAppPolicyGetProcessTerminationMethod(
  HANDLE processToken,
  AppPolicyProcessTerminationMethod* policy
);

LONG WINAPI MyAppPolicyGetThreadInitializationType(
  HANDLE processToken,
  AppPolicyThreadInitializationType* policy
);

LONG WINAPI MyAppPolicyGetWindowingModel(
  HANDLE processToken,
  AppPolicyWindowingModel* policy
);

BOOL WINAPI MyAreFileApisANSI();

BOOL WINAPI MyAssignProcessToJobObject(
  HANDLE hJob,
  HANDLE hProcess
);

BOOL WINAPI MyAttachConsole(
  DWORD dwProcessId
);

BOOL WINAPI MyBackupRead(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesRead,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
);

BOOL WINAPI MyBackupSeek(
  HANDLE hFile,
  DWORD dwLowBytesToSeek,
  DWORD dwHighBytesToSeek,
  LPDWORD lpdwLowByteSeeked,
  LPDWORD lpdwHighByteSeeked,
  LPVOID* lpContext
);

BOOL WINAPI MyBackupWrite(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
);

BOOL WINAPI MyBeep(
  DWORD dwFreq,
  DWORD dwDuration
);

HANDLE WINAPI MyBeginUpdateResourceA(
  LPCSTR pFileName,
  BOOL bDeleteExistingResources
);

HANDLE WINAPI MyBeginUpdateResourceW(
  LPCWSTR pFileName,
  BOOL bDeleteExistingResources
);

BOOL WINAPI MyBindIoCompletionCallback(
  HANDLE FilehHandle,
  LPOVERLAPPED_COMPLETION_ROUTINE Function,
  ULONG Flags
);

BOOL WINAPI MyBuildCommDCBA(
  LPCSTR lpDef,
  LPDCB lpDCB
);

BOOL WINAPI MyBuildCommDCBAndTimeoutsA(
  LPCSTR lpDef,
  LPDCB lpDCB,
  LPCOMMTIMEOUTS lpCommTimeouts
);

BOOL WINAPI MyBuildCommDCBAndTimeoutsW(
  LPCWSTR lpDef,
  LPDCB lpDCB,
  LPCOMMTIMEOUTS lpCommTimeouts
);

BOOL WINAPI MyBuildCommDCBW(
  LPCWSTR lpDef,
  LPDCB lpDCB
);

BOOL WINAPI MyCallbackMayRunLong(
  PTP_CALLBACK_INSTANCE pci
);

BOOL WINAPI MyCallNamedPipeA(
  LPCSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
);

BOOL WINAPI MyCallNamedPipeW(
  LPCWSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
);

BOOL WINAPI MyCancelIo(
  HANDLE hFile
);

BOOL WINAPI MyCancelIoEx(
  HANDLE hFile,
  LPOVERLAPPED lpOverlapped
);

BOOL WINAPI MyCancelSynchronousIo(
  HANDLE hThread
);

void WINAPI MyCancelThreadpoolIo(
  PTP_IO pio
);

BOOL WINAPI MyCancelWaitableTimer(
  HANDLE hTimer
);

BOOL WINAPI MyCeipIsOptedIn();

BOOL WINAPI MyChangeTimerQueueTimer(
  HANDLE TimerQueue,
  HANDLE Timer,
  ULONG DueTime,
  ULONG Period
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
  HANDLE hProcess,
  PBOOL pbDebuggerPresent
);

BOOL WINAPI MyCheckTokenCapability(
  HANDLE TokenHandle,
  PSID CapabilitySidToCheck,
  PBOOL HasCapability
);

BOOL WINAPI MyCheckTokenMembershipEx(
  HANDLE TokenHandle,
  PSID SidToCheck,
  DWORD Flags,
  PBOOL IsMember
);

BOOL WINAPI MyClearCommBreak(
  HANDLE hFile
);

BOOL WINAPI MyClearCommError(
  HANDLE hFile,
  LPDWORD lpErrors,
  LPCOMSTAT lpStat
);

BOOL WINAPI MyCloseHandle(
  HANDLE hObject
);

LONG WINAPI MyClosePackageInfo(
  PACKAGE_INFO_REFERENCE packageInfoReference
);

BOOLEAN WINAPI MyClosePrivateNamespace(
  HANDLE Handle,
  ULONG Flags
);

void WINAPI MyClosePseudoConsole(
  HPCON hPC
);

void WINAPI MyCloseThreadpool(
  PTP_POOL ptpp
);

void WINAPI MyCloseThreadpoolCleanupGroup(
  PTP_CLEANUP_GROUP ptpcg
);

void WINAPI MyCloseThreadpoolCleanupGroupMembers(
  PTP_CLEANUP_GROUP ptpcg,
  BOOL fCancelPendingCallbacks,
  PVOID pvCleanupContext
);

void WINAPI MyCloseThreadpoolIo(
  PTP_IO pio
);

void WINAPI MyCloseThreadpoolTimer(
  PTP_TIMER pti
);

void WINAPI MyCloseThreadpoolWait(
  PTP_WAIT pwa
);

void WINAPI MyCloseThreadpoolWork(
  PTP_WORK pwk
);

BOOL WINAPI MyCommConfigDialogA(
  LPCSTR lpszName,
  HWND hWnd,
  LPCOMMCONFIG lpCC
);

BOOL WINAPI MyCommConfigDialogW(
  LPCWSTR lpszName,
  HWND hWnd,
  LPCOMMCONFIG lpCC
);

LONG WINAPI MyCompareFileTime(
  const FILETIME* lpFileTime1,
  const FILETIME* lpFileTime2
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

BOOL WINAPI MyConnectNamedPipe(
  HANDLE hNamedPipe,
  LPOVERLAPPED lpOverlapped
);

BOOL WINAPI MyContinueDebugEvent(
  DWORD dwProcessId,
  DWORD dwThreadId,
  DWORD dwContinueStatus
);

LCID WINAPI MyConvertDefaultLocale(
  LCID Locale
);

BOOL WINAPI MyConvertFiberToThread();

LPVOID WINAPI MyConvertThreadToFiber(
  LPVOID lpParameter
);

LPVOID WINAPI MyConvertThreadToFiberEx(
  LPVOID lpParameter,
  DWORD dwFlags
);

BOOL WINAPI MyCopyContext(
  PCONTEXT Destination,
  DWORD ContextFlags,
  PCONTEXT Source
);

HRESULT WINAPI MyCopyFile2(
  PCWSTR pwszExistingFileName,
  PCWSTR pwszNewFileName,
  COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters
);

BOOL WINAPI MyCopyFileA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  BOOL bFailExists
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
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  BOOL bFailExists
);

HANDLE WINAPI MyCreateActCtxA(
  PCACTCTXA pActCtx
);

HANDLE WINAPI MyCreateActCtxW(
  PCACTCTXW pActCtx
);

HANDLE WINAPI MyCreateBoundaryDescriptorA(
  LPCSTR Name,
  ULONG Flags
);

HANDLE WINAPI MyCreateBoundaryDescriptorW(
  LPCWSTR Name,
  ULONG Flags
);

HANDLE WINAPI MyCreateConsoleScreenBuffer(
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  const SECURITY_ATTRIBUTES* lpSecurityAttributes,
  DWORD dwFlags,
  LPVOID lpScreenBuffer
);

BOOL WINAPI MyCreateDirectoryA(
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
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
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
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
  SIZE_T dwStackSize,
  LPFIBER_START_ROUTINE lpStartAddress,
  LPVOID lpParameter
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

HANDLE WINAPI MyCreatePrivateNamespaceA(
  LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes,
  LPVOID lpBoundaryDescriptor,
  LPCSTR lpAliasPrefix
);

HANDLE WINAPI MyCreatePrivateNamespaceW(
  LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes,
  LPVOID lpBoundaryDescriptor,
  LPCWSTR lpAliasPrefix
);

BOOL WINAPI MyCreateProcessA(
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandle,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

BOOL WINAPI MyCreateProcessAsUserA(
  HANDLE hToken,
  LPCSTR lpApplicationName,
  LPSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandle,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCSTR lpCurrentDirectory,
  LPSTARTUPINFOA lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

BOOL WINAPI MyCreateProcessAsUserW(
  HANDLE hToken,
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandle,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

BOOL WINAPI MyCreateProcessW(
  LPCWSTR lpApplicationName,
  LPWSTR lpCommandLine,
  LPSECURITY_ATTRIBUTES lpProcessAttributes,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  BOOL bInheritHandle,
  DWORD dwCreationFlags,
  LPVOID lpEnvironment,
  LPCWSTR lpCurrentDirectory,
  LPSTARTUPINFOW lpStartupInfo,
  LPPROCESS_INFORMATION lpProcessInformation
);

HRESULT WINAPI MyCreatePseudoConsole(
  COORD size,
  HANDLE hInput,
  HANDLE hOutput,
  DWORD dwFlags,
  HPCON* phPC
);

HANDLE WINAPI MyCreateRemoteThread(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAdress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
);

HANDLE WINAPI MyCreateRemoteThreadEx(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  LPDWORD lpThreadId
);

HANDLE WINAPI MyCreateSemaphoreA(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCSTR lpName
);

HANDLE WINAPI MyCreateSemaphoreExA(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateSemaphoreExW(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateSemaphoreW(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCWSTR lpName
);

BOOLEAN WINAPI MyCreateSymbolicLinkA(
  LPCSTR lpSymlinkFileName,
  LPCSTR lpTargetFileName,
  DWORD dwFlags
);

BOOLEAN WINAPI MyCreateSymbolicLinkTransactedA(
  LPCSTR lpSymlinkFileName,
  LPCSTR lpTargetFileName,
  DWORD dwFlags,
  HANDLE hTransaction
);

BOOLEAN WINAPI MyCreateSymbolicLinkTransactedW(
  LPCWSTR lpSymlinkFileName,
  LPCWSTR lpTargetFileName,
  DWORD dwFlags,
  HANDLE hTransaction
);

BOOLEAN WINAPI MyCreateSymbolicLinkW(
  LPCWSTR lpSymlinkFileName,
  LPCWSTR lpTargetFileName,
  DWORD dwFlags
);

DWORD WINAPI MyCreateTapePartition(
  HANDLE hDevice,
  DWORD dwPartitionMethod,
  DWORD dwCount,
  DWORD dwSize
);

HANDLE WINAPI MyCreateThread(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
);

PTP_POOL WINAPI MyCreateThreadpool(
  PVOID reserved
);

PTP_CLEANUP_GROUP WINAPI MyCreateThreadpoolCleanupGroup();

PTP_IO WINAPI MyCreateThreadpoolIo(
  HANDLE fl,
  PTP_WIN32_IO_CALLBACK pfnio,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
);

PTP_TIMER WINAPI MyCreateThreadpoolTimer(
  PTP_TIMER_CALLBACK pfnti,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
);

PTP_WAIT WINAPI MyCreateThreadpoolWait(
  PTP_WAIT_CALLBACK pfnwa,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
);

PTP_WORK WINAPI MyCreateThreadpoolWork(
  PTP_WORK_CALLBACK pfnwk,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
);

HANDLE WINAPI MyCreateTimerQueue();

BOOL WINAPI MyCreateTimerQueueTimer(
  PHANDLE phNewTimer,
  HANDLE TimerQueue,
  WAITORTIMERCALLBACK Callback,
  PVOID Parameter,
  DWORD DueTime,
  DWORD Period,
  ULONG Flags
);

HANDLE WINAPI MyCreateToolhelp32Snapshot(
  DWORD dwFlags,
  DWORD th32ProcessID
);

BOOL WINAPI MyCreateUmsCompletionList(
  PUMS_COMPLETION_LIST* UmsCompletionList
);

BOOL WINAPI MyCreateUmsThreadContext(
  PUMS_CONTEXT* lpUmsThread
);

HANDLE WINAPI MyCreateWaitableTimerExW(
  LPSECURITY_ATTRIBUTES lpTimerAttributes,
  LPCWSTR lpTimerName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
);

HANDLE WINAPI MyCreateWaitableTimerW(
  LPSECURITY_ATTRIBUTES lpTimerAttributes,
  BOOL bManualReset,
  LPCWSTR lpTimerName
);

BOOL WINAPI MyDeactivateActCtx(
  DWORD dwFlags,
  ULONG_PTR ulCookie
);

void WINAPI MyDebugBreak();

BOOL WINAPI MyDebugBreakProcess(
  HANDLE hProcess
);

BOOL WINAPI MyDebugSetProcessKillOnExit(
  BOOL KillOnExit
);

PVOID WINAPI MyDecodePointer(
  PVOID Ptr
);

PVOID WINAPI MyDecodeSystemPointer(
  PVOID Ptr
);

BOOL WINAPI MyDefineDosDeviceA(
  DWORD dwFlags,
  LPCSTR lpDeviceName,
  LPCSTR lpTargetPath
);

BOOL WINAPI MyDefineDosDeviceW(
  DWORD dwFlags,
  LPCWSTR lpDeviceName,
  LPCWSTR lpTargetPath
);

ATOM WINAPI MyDeleteAtom(
  ATOM nAtom
);

void WINAPI MyDeleteBoundaryDescriptor(
  HANDLE BoundaryDescriptor
);

void WINAPI MyDeleteCriticalSection(
  LPCRITICAL_SECTION lpCriticalSection
);

void WINAPI MyDeleteFiber(
  LPVOID lpFiber
);

BOOL WINAPI MyDeleteFileA(
  LPCSTR lpFileName
);

BOOL WINAPI MyDeleteFileTransactedA(
  LPCSTR lpFileName,
  HANDLE hTransactoin
);

BOOL WINAPI MyDeleteFileTransactedW(
  LPCWSTR lpFileName,
  HANDLE hTransactoin
);

BOOL WINAPI MyDeleteFileW(
  LPCWSTR lpFileName
);

void WINAPI MyDeleteProcThreadAttributeList(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
);

BOOL WINAPI MyDeleteSynchronizationBarrier(
  LPSYNCHRONIZATION_BARRIER lpBarrier
);

BOOL WINAPI MyDeleteTimerQueue(
  HANDLE TimerQueue
);

BOOL WINAPI MyDeleteTimerQueueEx(
  HANDLE TimerQueue,
  HANDLE CompletionEvent
);

BOOL WINAPI MyDeleteTimerQueueTimer(
  HANDLE TimerQueue,
  HANDLE Timer,
  HANDLE CompletionEvent
);

BOOL WINAPI MyDeleteUmsCompletionList(
  PUMS_COMPLETION_LIST UmsCompletionList
);

BOOL WINAPI MyDeleteUmsThreadContext(
  PUMS_CONTEXT UmsThread
);

BOOL WINAPI MyDeleteVolumeMountPointA(
  LPCSTR lpszVolumeMountPoint
);

BOOL WINAPI MyDeleteVolumeMountPointW(
  LPCWSTR lpszVolumeMountPoint
);

BOOL WINAPI MyDequeueUmsCompletionListItems(
  PUMS_COMPLETION_LIST UmsCompletionContext,
  DWORD WaitTime,
  PUMS_CONTEXT* UmsThreadList
);

BOOL WINAPI MyDeviceIoControl(
  HANDLE hDevice,
  DWORD dwIoControlCode,
  LPVOID lpInBuffer,
  DWORD nInBufferSize,
  LPVOID lpOutBuffer,
  DWORD nOutBufferSize,
  LPDWORD lpBytesReturned,
  LPOVERLAPPED lpOverlapped
);

BOOL WINAPI MyDisableThreadLibraryCalls(
  HMODULE hLibModule
);

DWORD WINAPI MyDisableThreadProfiling(
  HANDLE PerformanceDataHandle
);

void WINAPI MyDisassociateCurrentThreadFromCallback(
  PTP_CALLBACK_INSTANCE pci
);

DWORD WINAPI MyDiscardVirtualMemory(
  PVOID VirtualAddress,
  SIZE_T Size
);

///

HANDLE MyFindFirstFileA(LPCSTR, LPWIN32_FIND_DATAA);

HANDLE MyFindFirstFileW(LPCWSTR, LPWIN32_FIND_DATAW);

BOOL MyFindNextFileA(HANDLE, LPWIN32_FIND_DATAA);

BOOL MyFindNextFileW(HANDLE, LPWIN32_FIND_DATAW);

BOOL _CheckA(LPCSTR);

BOOL _CheckW(LPCWSTR);

#endif // _HOOK_FUNCTIONS_H
