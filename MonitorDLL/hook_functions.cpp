#include <windows.h>
#include <windowsceip.h>
#include <tlhelp32.h>
#include <string>

#include "hooker.h"
#include "hook_functions.h"

void WINAPI MyAcquireSRWLockExclusive(
  PSRWLOCK SRWLock
) {
  using func_type = decltype(&AcquireSRWLockExclusive);
  using real_type = decltype(&MyAcquireSRWLockExclusive);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);

  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AcquireSRWLockExclusive(SRWLock);
}

void WINAPI MyAcquireSRWLockShared(
  PSRWLOCK SRWLock
) {
  using func_type = decltype(&AcquireSRWLockShared);
  using real_type = decltype(&MyAcquireSRWLockShared);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AcquireSRWLockShared(SRWLock);
}

BOOL WINAPI MyActivateActCtx(
  HANDLE hActCtx,
  ULONG_PTR* lpCookie
) {
  using func_type = decltype(&ActivateActCtx);
  using real_type = decltype(&MyActivateActCtx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ActivateActCtx(hActCtx, lpCookie);
}

ATOM WINAPI MyAddAtomA(
  LPCSTR lpString
) {
  using func_type = decltype(&AddAtomA);
  using real_type = decltype(&MyAddAtomA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddAtomA(lpString);
}

ATOM WINAPI MyAddAtomW(
  LPCWSTR lpString
) {
  using func_type = decltype(&AddAtomW);
  using real_type = decltype(&MyAddAtomW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddAtomW(lpString);
}

BOOL WINAPI MyAddConsoleAliasA(
  LPSTR Source,
  LPSTR Target,
  LPSTR ExeName
) {
  using func_type = decltype(&AddConsoleAliasA);
  using real_type = decltype(&MyAddConsoleAliasA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddConsoleAliasA(Source, Target, ExeName);
}

BOOL WINAPI MyAddConsoleAliasW(
  LPWSTR Source,
  LPWSTR Target,
  LPWSTR ExeName
) {
  using func_type = decltype(&AddConsoleAliasW);
  using real_type = decltype(&MyAddConsoleAliasW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddConsoleAliasW(Source, Target, ExeName);
}

DLL_DIRECTORY_COOKIE WINAPI MyAddDllDirectory(
  PCWSTR NewDirectory
) {
  using func_type = decltype(&AddDllDirectory);
  using real_type = decltype(&MyAddDllDirectory);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddDllDirectory(NewDirectory);
}

BOOL WINAPI MyAddIntegrityLabelToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor,
  PSID IntegrityLabel
) {
  using func_type = decltype(&AddIntegrityLabelToBoundaryDescriptor);
  using real_type = decltype(&MyAddIntegrityLabelToBoundaryDescriptor);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddIntegrityLabelToBoundaryDescriptor(
    BoundaryDescriptor, IntegrityLabel
  );
}

void WINAPI MyAddRefActCtx(
  HANDLE hActCtx
) {
  using func_type = decltype(&AddRefActCtx);
  using real_type = decltype(&MyAddRefActCtx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddRefActCtx(hActCtx);
}

BOOL WINAPI MyAddResourceAttributeAce(
  PACL pAcl,
  DWORD dwAceRevision,
  DWORD AceFlags,
  DWORD AccessMask,
  PSID pSid,
  PCLAIM_SECURITY_ATTRIBUTES_INFORMATION pAttributeInfo,
  PDWORD pReturnLength
) {
  using func_type = decltype(&AddResourceAttributeAce);
  using real_type = decltype(&MyAddResourceAttributeAce);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddResourceAttributeAce(
    pAcl ,dwAceRevision, AceFlags, AccessMask, pSid, pAttributeInfo,
    pReturnLength
  );
}

BOOL WINAPI MyAddSecureMemoryCacheCallback(
  PSECURE_MEMORY_CACHE_CALLBACK pfnCallBack
) {
  using func_type = decltype(&AddSecureMemoryCacheCallback);
  using real_type = decltype(&MyAddSecureMemoryCacheCallback);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddSecureMemoryCacheCallback(pfnCallBack);
}

BOOL WINAPI MyAddSIDToBoundaryDescriptor(
  HANDLE* BoundaryDescriptor,
  PSID RequireSid
) {
  using func_type = decltype(&AddSIDToBoundaryDescriptor);
  using real_type = decltype(&MyAddSIDToBoundaryDescriptor);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddSIDToBoundaryDescriptor(BoundaryDescriptor, RequireSid);
}

PVOID WINAPI MyAddVectoredContinueHandler(
  ULONG First,
  PVECTORED_EXCEPTION_HANDLER Handler
) {
  using func_type = decltype(&AddVectoredContinueHandler);
  using real_type = decltype(&MyAddVectoredContinueHandler);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddVectoredContinueHandler(First, Handler);
}

PVOID WINAPI MyAddVectoredExceptionHandler(
  ULONG First,
  PVECTORED_EXCEPTION_HANDLER Handler
) {
  using func_type = decltype(&AddVectoredExceptionHandler);
  using real_type = decltype(&MyAddVectoredExceptionHandler);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AddVectoredExceptionHandler(First, Handler);
}

BOOL WINAPI MyAllocateUserPhysicalPages(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray
) {
  using func_type = decltype(&AllocateUserPhysicalPages);
  using real_type = decltype(&MyAllocateUserPhysicalPages);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AllocateUserPhysicalPages(hProcess, NumberOfPages, PageArray);
}

BOOL WINAPI MyAllocateUserPhysicalPagesNuma(
  HANDLE hProcess,
  PULONG_PTR NumberOfPages,
  PULONG_PTR PageArray,
  DWORD nndPreferred
) {
  using func_type = decltype(&AllocateUserPhysicalPagesNuma);
  using real_type = decltype(&MyAllocateUserPhysicalPagesNuma);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AllocateUserPhysicalPagesNuma(
    hProcess, NumberOfPages, PageArray, nndPreferred
  );
}

BOOL WINAPI MyAllocConsole() {
  using func_type = decltype(&AllocConsole);
  using real_type = decltype(&MyAllocConsole);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AllocConsole();
}

void WINAPI MyApplicationRecoveryFinished(
  BOOL bSuccess
) {
  using func_type = decltype(&ApplicationRecoveryFinished);
  using real_type = decltype(&MyApplicationRecoveryFinished);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ApplicationRecoveryFinished(bSuccess);
}

HRESULT WINAPI MyApplicationRecoveryInProgress(
  PBOOL pbCancelled
) {
  using func_type = decltype(&ApplicationRecoveryInProgress);
  using real_type = decltype(&MyApplicationRecoveryInProgress);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ApplicationRecoveryInProgress(pbCancelled);
}

LONG WINAPI MyAppPolicyGetClrCompat(
  HANDLE processToken,
  AppPolicyClrCompat* policy
) {
  using func_type = decltype(&AppPolicyGetClrCompat);
  using real_type = decltype(&MyAppPolicyGetClrCompat);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AppPolicyGetClrCompat(processToken, policy);
}

LONG WINAPI MyAppPolicyGetMediaFoundationCodecLoading(
  HANDLE processToken,
  AppPolicyMediaFoundationCodecLoading* policy
) {
  using func_type = decltype(&AppPolicyGetMediaFoundationCodecLoading);
  using real_type = decltype(&MyAppPolicyGetMediaFoundationCodecLoading);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AppPolicyGetMediaFoundationCodecLoading(processToken, policy);
}

LONG WINAPI MyAppPolicyGetProcessTerminationMethod(
  HANDLE processToken,
  AppPolicyProcessTerminationMethod* policy
) {
  using func_type = decltype(&AppPolicyGetProcessTerminationMethod);
  using real_type = decltype(&MyAppPolicyGetProcessTerminationMethod);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AppPolicyGetProcessTerminationMethod(processToken, policy);
}

LONG WINAPI MyAppPolicyGetThreadInitializationType(
  HANDLE processToken,
  AppPolicyThreadInitializationType* policy
) {
  using func_type = decltype(&AppPolicyGetThreadInitializationType);
  using real_type = decltype(&MyAppPolicyGetThreadInitializationType);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AppPolicyGetThreadInitializationType(processToken, policy);
}

LONG WINAPI MyAppPolicyGetWindowingModel(
  HANDLE processToken,
  AppPolicyWindowingModel* policy
) {
  using func_type = decltype(&AppPolicyGetWindowingModel);
  using real_type = decltype(&MyAppPolicyGetWindowingModel);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AppPolicyGetWindowingModel(processToken, policy);
}

BOOL WINAPI MyAreFileApisANSI() {
  using func_type = decltype(&AreFileApisANSI);
  using real_type = decltype(&MyAreFileApisANSI);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AreFileApisANSI();
}

BOOL WINAPI MyAssignProcessToJobObject(
  HANDLE hJob,
  HANDLE hProcess
) {
  using func_type = decltype(&AssignProcessToJobObject);
  using real_type = decltype(&MyAssignProcessToJobObject);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AssignProcessToJobObject(hJob, hProcess);
}

BOOL WINAPI MyAttachConsole(
  DWORD dwProcessId
) {
  using func_type = decltype(&AttachConsole);
  using real_type = decltype(&MyAttachConsole);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return AttachConsole(dwProcessId);
}

BOOL WINAPI MyBackupRead(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToRead,
  LPDWORD lpNumberOfBytesRead,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupRead);
  using real_type = decltype(&MyBackupRead);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BackupRead(
    hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, bAbort,
    bProcessSecurity, lpContext
  );
}

BOOL WINAPI MyBackupSeek(
  HANDLE hFile,
  DWORD dwLowBytesToSeek,
  DWORD dwHighBytesToSeek,
  LPDWORD lpdwLowByteSeeked,
  LPDWORD lpdwHighByteSeeked,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupSeek);
  using real_type = decltype(&MyBackupSeek);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BackupSeek(
    hFile, dwLowBytesToSeek, dwHighBytesToSeek, lpdwLowByteSeeked,
    lpdwHighByteSeeked, lpContext
  );
}

BOOL WINAPI MyBackupWrite(
  HANDLE hFile,
  LPBYTE lpBuffer,
  DWORD nNumberOfBytesToWrite,
  LPDWORD lpNumberOfBytesWritten,
  BOOL bAbort,
  BOOL bProcessSecurity,
  LPVOID* lpContext
) {
  using func_type = decltype(&BackupWrite);
  using real_type = decltype(&MyBackupWrite);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BackupWrite(
    hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, bAbort,
    bProcessSecurity, lpContext
  );
}

BOOL WINAPI MyBeep(
  DWORD dwFreq,
  DWORD dwDuration
) {
  using func_type = decltype(&Beep);
  using real_type = decltype(&MyBeep);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return Beep(dwFreq, dwDuration);
}

HANDLE WINAPI MyBeginUpdateResourceA(
  LPCSTR pFileName,
  BOOL bDeleteExistingResources
) {
  using func_type = decltype(&BeginUpdateResourceA);
  using real_type = decltype(&MyBeginUpdateResourceA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BeginUpdateResourceA(pFileName, bDeleteExistingResources);
}

HANDLE WINAPI MyBeginUpdateResourceW(
  LPCWSTR pFileName,
  BOOL bDeleteExistingResources
) {
  using func_type = decltype(&BeginUpdateResourceW);
  using real_type = decltype(&MyBeginUpdateResourceW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BeginUpdateResourceW(pFileName, bDeleteExistingResources);
}

BOOL WINAPI MyBindIoCompletionCallback(
  HANDLE FilehHandle,
  LPOVERLAPPED_COMPLETION_ROUTINE Function,
  ULONG Flags
) {
  using func_type = decltype(&BindIoCompletionCallback);
  using real_type = decltype(&MyBindIoCompletionCallback);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BindIoCompletionCallback(FilehHandle, Function, Flags);
}

BOOL WINAPI MyBuildCommDCBA(
  LPCSTR lpDef,
  LPDCB lpDCB
) {
  using func_type = decltype(&BuildCommDCBA);
  using real_type = decltype(&MyBuildCommDCBA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BuildCommDCBA(lpDef, lpDCB);
}

BOOL WINAPI MyBuildCommDCBAndTimeoutsA(
  LPCSTR lpDef,
  LPDCB lpDCB,
  LPCOMMTIMEOUTS lpCommTimeouts
) {
  using func_type = decltype(&BuildCommDCBAndTimeoutsA);
  using real_type = decltype(&MyBuildCommDCBAndTimeoutsA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BuildCommDCBAndTimeoutsA(lpDef, lpDCB, lpCommTimeouts);
}

BOOL WINAPI MyBuildCommDCBAndTimeoutsW(
  LPCWSTR lpDef,
  LPDCB lpDCB,
  LPCOMMTIMEOUTS lpCommTimeouts
) {
  using func_type = decltype(&BuildCommDCBAndTimeoutsW);
  using real_type = decltype(&MyBuildCommDCBAndTimeoutsW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BuildCommDCBAndTimeoutsW(lpDef, lpDCB, lpCommTimeouts);
}

BOOL WINAPI MyBuildCommDCBW(
  LPCWSTR lpDef,
  LPDCB lpDCB
) {
  using func_type = decltype(&BuildCommDCBW);
  using real_type = decltype(&MyBuildCommDCBW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return BuildCommDCBW(lpDef, lpDCB);
}

BOOL WINAPI MyCallbackMayRunLong(
  PTP_CALLBACK_INSTANCE pci
) {
  using func_type = decltype(&CallbackMayRunLong);
  using real_type = decltype(&MyCallbackMayRunLong);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CallbackMayRunLong(pci);
}

BOOL WINAPI MyCallNamedPipeA(
  LPCSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
) {
  using func_type = decltype(&CallNamedPipeA);
  using real_type = decltype(&MyCallNamedPipeA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CallNamedPipeA(
    lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize,
    lpBytesRead, nTimeOut
  );
}

BOOL WINAPI MyCallNamedPipeW(
  LPCWSTR  lpNamedPipeName,
  LPVOID  lpInBuffer,
  DWORD   nInBufferSize,
  LPVOID  lpOutBuffer,
  DWORD   nOutBufferSize,
  LPDWORD lpBytesRead,
  DWORD   nTimeOut
) {
  using func_type = decltype(&CallNamedPipeW);
  using real_type = decltype(&MyCallNamedPipeW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CallNamedPipeW(
    lpNamedPipeName, lpInBuffer, nInBufferSize, lpOutBuffer, nOutBufferSize,
    lpBytesRead, nTimeOut
  );
}

BOOL WINAPI MyCancelIo(
  HANDLE hFile
) {
  using func_type = decltype(&CancelIo);
  using real_type = decltype(&MyCancelIo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CancelIo(hFile);
}

BOOL WINAPI MyCancelIoEx(
  HANDLE hFile,
  LPOVERLAPPED lpOverlapped
) {
  using func_type = decltype(&CancelIoEx);
  using real_type = decltype(&MyCancelIoEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CancelIoEx(hFile, lpOverlapped);
}

BOOL WINAPI MyCancelSynchronousIo(
  HANDLE hThread
) {
  using func_type = decltype(&CancelSynchronousIo);
  using real_type = decltype(&MyCancelSynchronousIo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CancelSynchronousIo(hThread);
}

void WINAPI MyCancelThreadpoolIo(
  PTP_IO pio
) {
  using func_type = decltype(&CancelThreadpoolIo);
  using real_type = decltype(&MyCancelThreadpoolIo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CancelThreadpoolIo(pio);
}

BOOL WINAPI MyCancelWaitableTimer(
  HANDLE hTimer
) {
  using func_type = decltype(&CancelWaitableTimer);
  using real_type = decltype(&MyCancelWaitableTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CancelWaitableTimer(hTimer);
}

BOOL WINAPI MyCeipIsOptedIn() {
  using func_type = decltype(&CeipIsOptedIn);
  using real_type = decltype(&MyCeipIsOptedIn);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CeipIsOptedIn();
}

BOOL WINAPI MyChangeTimerQueueTimer(
  HANDLE TimerQueue,
  HANDLE Timer,
  ULONG DueTime,
  ULONG Period
) {
  using func_type = decltype(&ChangeTimerQueueTimer);
  using real_type = decltype(&MyChangeTimerQueueTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ChangeTimerQueueTimer(TimerQueue, Timer, DueTime, Period);
}

BOOL WINAPI MyCheckNameLegalDOS8Dot3A(
  LPCSTR lpName,
  LPSTR lpOemName,
  DWORD OemNameSize,
  PBOOL pbNameContainsSpaces,
  PBOOL pbNameLegal
) {
  using func_type = decltype(&CheckNameLegalDOS8Dot3A);
  using real_type = decltype(&MyCheckNameLegalDOS8Dot3A);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CheckNameLegalDOS8Dot3A(
    lpName, lpOemName, OemNameSize, pbNameContainsSpaces, pbNameLegal
  );
}

BOOL WINAPI MyCheckNameLegalDOS8Dot3W(
  LPCWSTR lpName,
  LPSTR lpOemName,
  DWORD OemNameSize,
  PBOOL pbNameContainsSpaces,
  PBOOL pbNameLegal
) {
  using func_type = decltype(&CheckNameLegalDOS8Dot3W);
  using real_type = decltype(&MyCheckNameLegalDOS8Dot3W);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CheckNameLegalDOS8Dot3W(
    lpName, lpOemName, OemNameSize, pbNameContainsSpaces, pbNameLegal
  );
}

BOOL WINAPI MyCheckRemoteDebuggerPresent(
  HANDLE hProcess,
  PBOOL pbDebuggerPresent
) {
  using func_type = decltype(&CheckRemoteDebuggerPresent);
  using real_type = decltype(&MyCheckRemoteDebuggerPresent);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CheckRemoteDebuggerPresent(hProcess, pbDebuggerPresent);
}


BOOL WINAPI MyCheckTokenCapability(
  HANDLE TokenHandle,
  PSID CapabilitySidToCheck,
  PBOOL HasCapability
) {
  using func_type = decltype(&CheckTokenCapability);
  using real_type = decltype(&MyCheckTokenCapability);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CheckTokenCapability(TokenHandle, CapabilitySidToCheck, HasCapability);
}

BOOL WINAPI MyCheckTokenMembershipEx(
  HANDLE TokenHandle,
  PSID SidToCheck,
  DWORD Flags,
  PBOOL IsMember
) {
  using func_type = decltype(&CheckTokenMembershipEx);
  using real_type = decltype(&MyCheckTokenMembershipEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CheckTokenMembershipEx(TokenHandle, SidToCheck, Flags, IsMember);
}

BOOL WINAPI MyClearCommBreak(
  HANDLE hFile
) {
  using func_type = decltype(&ClearCommBreak);
  using real_type = decltype(&MyClearCommBreak);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ClearCommBreak(hFile);
}

BOOL WINAPI MyClearCommError(
  HANDLE hFile,
  LPDWORD lpErrors,
  LPCOMSTAT lpStat
) {
  using func_type = decltype(&ClearCommError);
  using real_type = decltype(&MyClearCommError);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ClearCommError(hFile, lpErrors, lpStat);
}

BOOL MyCloseHandle(
  HANDLE hObject
) {
  using func_type = decltype(&CloseHandle);
  using real_type = decltype(&MyCloseHandle);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseHandle(hObject);
}

LONG WINAPI MyClosePackageInfo(
  PACKAGE_INFO_REFERENCE packageInfoReference
) {
  using func_type = decltype(&ClosePackageInfo);
  using real_type = decltype(&MyClosePackageInfo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ClosePackageInfo(packageInfoReference);
}

BOOLEAN WINAPI MyClosePrivateNamespace(
  HANDLE Handle,
  ULONG Flags
) {
  using func_type = decltype(&ClosePrivateNamespace);
  using real_type = decltype(&MyClosePrivateNamespace);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ClosePrivateNamespace(Handle, Flags);
}

void WINAPI MyClosePseudoConsole(
  HPCON hPC
) {
  using func_type = decltype(&ClosePseudoConsole);
  using real_type = decltype(&MyClosePseudoConsole);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ClosePseudoConsole(hPC);
}


void WINAPI MyCloseThreadpool(
  PTP_POOL ptpp
) {
  using func_type = decltype(&CloseThreadpool);
  using real_type = decltype(&MyCloseThreadpool);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpool(ptpp);
}

void WINAPI MyCloseThreadpoolCleanupGroup(
  PTP_CLEANUP_GROUP ptpcg
) {
  using func_type = decltype(&CloseThreadpoolCleanupGroup);
  using real_type = decltype(&MyCloseThreadpoolCleanupGroup);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolCleanupGroup(ptpcg);
}

void WINAPI MyCloseThreadpoolCleanupGroupMembers(
  PTP_CLEANUP_GROUP ptpcg,
  BOOL fCancelPendingCallbacks,
  PVOID pvCleanupContext
) {
  using func_type = decltype(&CloseThreadpoolCleanupGroupMembers);
  using real_type = decltype(&MyCloseThreadpoolCleanupGroupMembers);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolCleanupGroupMembers(
    ptpcg, fCancelPendingCallbacks, pvCleanupContext
  );
}

void WINAPI MyCloseThreadpoolIo(
  PTP_IO pio
) {
  using func_type = decltype(&CloseThreadpoolIo);
  using real_type = decltype(&MyCloseThreadpoolIo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolIo(pio);
}

void WINAPI MyCloseThreadpoolTimer(
  PTP_TIMER pti
) {
  using func_type = decltype(&CloseThreadpoolTimer);
  using real_type = decltype(&MyCloseThreadpoolTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolTimer(pti);
}

void WINAPI MyCloseThreadpoolWait(
  PTP_WAIT pwa
) {
  using func_type = decltype(&CloseThreadpoolWait);
  using real_type = decltype(&MyCloseThreadpoolWait);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolWait(pwa);
}

void WINAPI MyCloseThreadpoolWork(
  PTP_WORK pwk
) {
  using func_type = decltype(&CloseThreadpoolWork);
  using real_type = decltype(&MyCloseThreadpoolWork);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CloseThreadpoolWork(pwk);
}

BOOL WINAPI MyCommConfigDialogA(
  LPCSTR lpszName,
  HWND hWnd,
  LPCOMMCONFIG lpCC
) {
  using func_type = decltype(&CommConfigDialogA);
  using real_type = decltype(&MyCommConfigDialogA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CommConfigDialogA(lpszName, hWnd, lpCC);
}

BOOL WINAPI MyCommConfigDialogW(
  LPCWSTR lpszName,
  HWND hWnd,
  LPCOMMCONFIG lpCC
) {
  using func_type = decltype(&CommConfigDialogW);
  using real_type = decltype(&MyCommConfigDialogW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CommConfigDialogW(lpszName, hWnd, lpCC);
}

LONG WINAPI MyCompareFileTime(
  const FILETIME* lpFileTime1,
  const FILETIME* lpFileTime2
) {
  using func_type = decltype(&CompareFileTime);
  using real_type = decltype(&MyCompareFileTime);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CompareFileTime(lpFileTime1, lpFileTime2);
}

int WINAPI MyCompareStringA(
  LCID Locale,
  DWORD dwCmpFlags,
  PCNZCH lpString1,
  int cchCount1,
  PCNZCH lpString2,
  int cchCount2
) {
  using func_type = decltype(&CompareStringA);
  using real_type = decltype(&MyCompareStringA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CompareStringA(
    Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2
  );
}

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
) {
  using func_type = decltype(&CompareStringEx);
  using real_type = decltype(&MyCompareStringEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CompareStringEx(
    lpLocaleName, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2,
    lpVersionInformation, lpReserved, lParam
  );
}

int WINAPI MyCompareStringOrdinal(
  _In_NLS_string_(cchCount1)LPCWCH lpString1,
  int cchCount1,
  _In_NLS_string_(cchCount2)LPCWCH lpString2,
  int cchCount2,
  BOOL bIgnoreCase
) {
  using func_type = decltype(&CompareStringOrdinal);
  using real_type = decltype(&MyCompareStringOrdinal);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CompareStringOrdinal(
    lpString1, cchCount1, lpString2, cchCount2, bIgnoreCase
  );
}

int WINAPI MyCompareStringW(
  LCID Locale,
  DWORD dwCmpFlags,
  _In_NLS_string_(cchCount1)PCNZWCH lpString1,
  int cchCount1,
  _In_NLS_string_(cchCount2)PCNZWCH lpString2,
  int cchCount2
) {
  using func_type = decltype(&CompareStringW);
  using real_type = decltype(&MyCompareStringW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CompareStringW(
    Locale, dwCmpFlags, lpString1, cchCount1, lpString2, cchCount2
  );
}

BOOL WINAPI MyConnectNamedPipe(
  HANDLE hNamedPipe,
  LPOVERLAPPED lpOverlapped
) {
  using func_type = decltype(&ConnectNamedPipe);
  using real_type = decltype(&MyConnectNamedPipe);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ConnectNamedPipe(hNamedPipe, lpOverlapped);
}

BOOL WINAPI MyContinueDebugEvent(
  DWORD dwProcessId,
  DWORD dwThreadId,
  DWORD dwContinueStatus
) {
  using func_type = decltype(&ContinueDebugEvent);
  using real_type = decltype(&MyContinueDebugEvent);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ContinueDebugEvent(dwProcessId, dwThreadId, dwContinueStatus);
}

LCID WINAPI MyConvertDefaultLocale(
  LCID Locale
) {
  using func_type = decltype(&ConvertDefaultLocale);
  using real_type = decltype(&MyConvertDefaultLocale);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ConvertDefaultLocale(Locale);
}

BOOL WINAPI MyConvertFiberToThread() {
  using func_type = decltype(&ConvertFiberToThread);
  using real_type = decltype(&MyConvertFiberToThread);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ConvertFiberToThread();
}

LPVOID WINAPI MyConvertThreadToFiber(
  LPVOID lpParameter
) {
  using func_type = decltype(&ConvertThreadToFiber);
  using real_type = decltype(&MyConvertThreadToFiber);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ConvertThreadToFiber(lpParameter);
}

LPVOID WINAPI MyConvertThreadToFiberEx(
  LPVOID lpParameter,
  DWORD dwFlags
) {
  using func_type = decltype(&ConvertThreadToFiberEx);
  using real_type = decltype(&MyConvertThreadToFiberEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return ConvertThreadToFiberEx(lpParameter, dwFlags);
}

BOOL WINAPI MyCopyContext(
  PCONTEXT Destination,
  DWORD ContextFlags,
  PCONTEXT Source
) {
  using func_type = decltype(&CopyContext);
  using real_type = decltype(&MyCopyContext);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyContext(Destination, ContextFlags, Source);
}

HRESULT WINAPI MyCopyFile2(
  PCWSTR pwszExistingFileName,
  PCWSTR pwszNewFileName,
  COPYFILE2_EXTENDED_PARAMETERS* pExtendedParameters
) {
  using func_type = decltype(&CopyFile2);
  using real_type = decltype(&MyCopyFile2);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFile2(pwszExistingFileName, pwszNewFileName, pExtendedParameters);
}


BOOL WINAPI MyCopyFileA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  BOOL bFailExists
) {
  using func_type = decltype(&CopyFileA);
  using real_type = decltype(&MyCopyFileA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileA(lpExistingFileName, lpNewFileName, bFailExists);
}

BOOL WINAPI MyCopyFileExA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags
) {
  using func_type = decltype(&CopyFileExA);
  using real_type = decltype(&MyCopyFileExA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileExA(
    lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel,
    dwCopyFlags
  );
}

BOOL WINAPI MyCopyFileExW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags
) {
  using func_type = decltype(&CopyFileExW);
  using real_type = decltype(&MyCopyFileExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileExW(
    lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel,
    dwCopyFlags
  );
}

BOOL WINAPI MyCopyFileTransactedA(
  LPCSTR lpExistingFileName,
  LPCSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags,
  HANDLE hTransaction
) {
  using func_type = decltype(&CopyFileTransactedA);
  using real_type = decltype(&MyCopyFileTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileTransactedA(
    lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel,
    dwCopyFlags, hTransaction
  );
}

BOOL WINAPI MyCopyFileTransactedW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  LPPROGRESS_ROUTINE lpProgressRoutine,
  LPVOID lpData,
  LPBOOL pbCancel,
  DWORD dwCopyFlags,
  HANDLE hTransaction
) {
  using func_type = decltype(&CopyFileTransactedW);
  using real_type = decltype(&MyCopyFileTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileTransactedW(
    lpExistingFileName, lpNewFileName, lpProgressRoutine, lpData, pbCancel,
    dwCopyFlags, hTransaction
  );
}

BOOL WINAPI MyCopyFileW(
  LPCWSTR lpExistingFileName,
  LPCWSTR lpNewFileName,
  BOOL bFailExists
) {
  using func_type = decltype(&CopyFileW);
  using real_type = decltype(&MyCopyFileW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CopyFileW(lpExistingFileName, lpNewFileName, bFailExists);
}

HANDLE WINAPI MyCreateActCtxA(
  PCACTCTXA pActCtx
) {
  using func_type = decltype(&CreateActCtxA);
  using real_type = decltype(&MyCreateActCtxA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateActCtxA(pActCtx);
}

HANDLE WINAPI MyCreateActCtxW(
  PCACTCTXW pActCtx
) {
  using func_type = decltype(&CreateActCtxW);
  using real_type = decltype(&MyCreateActCtxW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateActCtxW(pActCtx);
}

HANDLE WINAPI MyCreateBoundaryDescriptorA(
  LPCSTR Name,
  ULONG Flags
) {
  using func_type = decltype(&CreateBoundaryDescriptorA);
  using real_type = decltype(&MyCreateBoundaryDescriptorA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateBoundaryDescriptorA(Name, Flags);
}

HANDLE WINAPI MyCreateBoundaryDescriptorW(
  LPCWSTR Name,
  ULONG Flags
) {
  using func_type = decltype(&CreateBoundaryDescriptorW);
  using real_type = decltype(&MyCreateBoundaryDescriptorW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateBoundaryDescriptorW(Name, Flags);
}

HANDLE WINAPI MyCreateConsoleScreenBuffer(
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  const SECURITY_ATTRIBUTES* lpSecurityAttributes,
  DWORD dwFlags,
  LPVOID lpScreenBuffer
) {
  using func_type = decltype(&CreateConsoleScreenBuffer);
  using real_type = decltype(&MyCreateConsoleScreenBuffer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateConsoleScreenBuffer(
    dwDesiredAccess, dwSharedMode, lpSecurityAttributes, dwFlags, lpScreenBuffer
  );
}

BOOL WINAPI MyCreateDirectoryA(
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateDirectoryA);
  using real_type = decltype(&MyCreateDirectoryA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryA(lpPathName, lpSecurityAttributes);
}

BOOL WINAPI MyCreateDirectoryExA(
  LPCSTR lpTempalteDirectory,
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateDirectoryExA);
  using real_type = decltype(&MyCreateDirectoryExA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryExA(
    lpTempalteDirectory , lpPathName, lpSecurityAttributes
  );
}


BOOL WINAPI MyCreateDirectoryExW(
  LPCWSTR lpTempalteDirectory,
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateDirectoryExW);
  using real_type = decltype(&MyCreateDirectoryExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryExW(
    lpTempalteDirectory , lpPathName, lpSecurityAttributes
  );
}

BOOL WINAPI MyCreateDirectoryTransactedA(
  LPCSTR lpTempalteDirectory,
  LPCSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTrancation
) {
  using func_type = decltype(&CreateDirectoryTransactedA);
  using real_type = decltype(&MyCreateDirectoryTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryTransactedA(
    lpTempalteDirectory , lpPathName, lpSecurityAttributes, hTrancation
  );
}

BOOL WINAPI MyCreateDirectoryTransactedW(
  LPCWSTR lpTempalteDirectory,
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTrancation
) {
  using func_type = decltype(&CreateDirectoryTransactedW);
  using real_type = decltype(&MyCreateDirectoryTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryTransactedW(
    lpTempalteDirectory , lpPathName, lpSecurityAttributes, hTrancation
  );
}


BOOL WINAPI MyCreateDirectoryW(
  LPCWSTR lpPathName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateDirectoryW);
  using real_type = decltype(&MyCreateDirectoryW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateDirectoryW(lpPathName, lpSecurityAttributes);
}

LPVOID WINAPI MyCreateEnclave(
  HANDLE hProcess,
  LPVOID lpAddress,
  SIZE_T dwSize,
  SIZE_T dwInitialCommitment,
  DWORD flEnclaveType,
  LPCVOID lpEnclaveInformation,
  DWORD dwInfoLength,
  LPDWORD lpEnclaveError
) {
  using func_type = decltype(&CreateEnclave);
  using real_type = decltype(&MyCreateEnclave);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateEnclave(
    hProcess, lpAddress, dwSize, dwInitialCommitment, flEnclaveType,
    lpEnclaveInformation, dwInfoLength, lpEnclaveError
  );
}


HANDLE WINAPI MyCreateEventA(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  BOOL bManualReset,
  BOOL bInitialState,
  LPCSTR lpName
) {
  using func_type = decltype(&CreateEventA);
  using real_type = decltype(&MyCreateEventA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateEventA(lpEventAttributes, bManualReset, bInitialState, lpName);
}

HANDLE WINAPI MyCreateEventExA(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateEventExA);
  using real_type = decltype(&MyCreateEventExA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateEventExA(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
}

HANDLE WINAPI MyCreateEventExW(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateEventExW);
  using real_type = decltype(&MyCreateEventExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateEventExW(lpEventAttributes, lpName, dwFlags, dwDesiredAccess);
}


HANDLE WINAPI MyCreateEventW(
  LPSECURITY_ATTRIBUTES lpEventAttributes,
  BOOL bManualReset,
  BOOL bInitialState,
  LPCWSTR lpName
) {
  using func_type = decltype(&CreateEventW);
  using real_type = decltype(&MyCreateEventW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateEventW(lpEventAttributes, bManualReset, bInitialState, lpName);
}

LPVOID WINAPI MyCreateFiber(
  SIZE_T dwStackSize,
  LPFIBER_START_ROUTINE lpStartAddress,
  LPVOID lpParameter
) {
  using func_type = decltype(&CreateFiber);
  using real_type = decltype(&MyCreateFiber);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFiber(dwStackSize, lpStartAddress, lpParameter);
}

LPVOID WINAPI MyCreateFiberEx(
  SIZE_T dwStackCommitSize,
  SIZE_T dwStackReservedSize,
  DWORD dwFlags,
  LPFIBER_START_ROUTINE lpStartAddress,
  LPVOID lpParameter
) {
  using func_type = decltype(&CreateFiberEx);
  using real_type = decltype(&MyCreateFiberEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFiberEx(
    dwStackCommitSize, dwStackReservedSize, dwFlags, lpStartAddress, lpParameter
  );
}

HANDLE WINAPI MyCreateFile2(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  DWORD dwCreationDisposition,
  LPCREATEFILE2_EXTENDED_PARAMETERS pCreateExParams
) {
  using func_type = decltype(&CreateFile2);
  using real_type = decltype(&MyCreateFile2);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFile2(
    lpFileName, dwDesiredAccess, dwSharedMode, dwCreationDisposition,
    pCreateExParams
  );
}

HANDLE WINAPI MyCreateFileA(
  LPCSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
) {
  using func_type = decltype(&CreateFileA);
  using real_type = decltype(&MyCreateFileA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  if (_CheckA(lpFileName)) { return INVALID_HANDLE_VALUE; }

  return CreateFileA(
    lpFileName, dwDesiredAccess, dwSharedMode, lpSecurityAttributes,
    dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
  );
}

HANDLE WINAPI MyCreateFileMappingA(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCSTR lpName
) {
  using func_type = decltype(&CreateFileMappingA);
  using real_type = decltype(&MyCreateFileMappingA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileMappingA(
    hFile, lpSecurityAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
    lpName
  );
}

HANDLE WINAPI MyCreateFileMappingFromApp(
  HANDLE hFile,
  PSECURITY_ATTRIBUTES SecurityAttributes,
  ULONG PageProtection,
  ULONG64 MaximumSize,
  PCWSTR Name
) {
  using func_type = decltype(&CreateFileMappingFromApp);
  using real_type = decltype(&MyCreateFileMappingFromApp);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileMappingFromApp(
    hFile, SecurityAttributes, PageProtection, MaximumSize, Name
  );
}

HANDLE WINAPI MyCreateFileMappingNumaA(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProject,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCSTR lpName,
  DWORD nndPreferred
) {
  using func_type = decltype(&CreateFileMappingNumaA);
  using real_type = decltype(&MyCreateFileMappingNumaA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileMappingNumaA(
    hFile, lpFileMappingAttributes, flProject, dwMaximumSizeHigh,
    dwMaximumSizeLow, lpName, nndPreferred
  );
}

HANDLE WINAPI MyCreateFileMappingNumaW(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpFileMappingAttributes,
  DWORD flProject,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName,
  DWORD nndPreferred
) {
  using func_type = decltype(&CreateFileMappingNumaW);
  using real_type = decltype(&MyCreateFileMappingNumaW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileMappingNumaW(
    hFile, lpFileMappingAttributes, flProject, dwMaximumSizeHigh,
    dwMaximumSizeLow, lpName, nndPreferred
  );
}

HANDLE WINAPI MyCreateFileMappingW(
  HANDLE hFile,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD flProtect,
  DWORD dwMaximumSizeHigh,
  DWORD dwMaximumSizeLow,
  LPCWSTR lpName
) {
  using func_type = decltype(&CreateFileMappingW);
  using real_type = decltype(&MyCreateFileMappingW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileMappingW(
    hFile, lpSecurityAttributes, flProtect, dwMaximumSizeHigh, dwMaximumSizeLow,
    lpName
  );
}

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
) {
  using func_type = decltype(&CreateFileTransactedA);
  using real_type = decltype(&MyCreateFileTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileTransactedA(
    lpFileName, dwDesiredAccess, dwSharedMode, lpSecurityAttributes,
    dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction,
    pusMiniVersion, lpExtendedParameter
  );
}

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
) {
  using func_type = decltype(&CreateFileTransactedW);
  using real_type = decltype(&MyCreateFileTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateFileTransactedW(
    lpFileName, dwDesiredAccess, dwSharedMode, lpSecurityAttributes,
    dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile, hTransaction,
    pusMiniVersion, lpExtendedParameter
  );
}

HANDLE WINAPI MyCreateFileW(
  LPCWSTR lpFileName,
  DWORD dwDesiredAccess,
  DWORD dwSharedMode,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  DWORD dwCreationDisposition,
  DWORD dwFlagsAndAttributes,
  HANDLE hTemplateFile
) {
  using func_type = decltype(&CreateFileW);
  using real_type = decltype(&MyCreateFileW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  if (_CheckW(lpFileName)) { return INVALID_HANDLE_VALUE; }

  return CreateFileW(
    lpFileName, dwDesiredAccess, dwSharedMode, lpSecurityAttributes,
    dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile
  );
}

BOOL WINAPI MyCreateHardLinkA(
  LPCSTR lpFileName,
  LPCSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateHardLinkA);
  using real_type = decltype(&MyCreateHardLinkA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateHardLinkA(lpFileName, lpExistingFileName, lpSecurityAttributes);
}

BOOL WINAPI MyCreateHardLinkTransactedA(
  LPCSTR lpFileName,
  LPCSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTransaction
) {
  using func_type = decltype(&CreateHardLinkTransactedA);
  using real_type = decltype(&MyCreateHardLinkTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateHardLinkTransactedA(
    lpFileName, lpExistingFileName, lpSecurityAttributes, hTransaction
  );
}

BOOL WINAPI MyCreateHardLinkTransactedW(
  LPCWSTR lpFileName,
  LPCWSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  HANDLE hTransaction
) {
  using func_type = decltype(&CreateHardLinkTransactedW);
  using real_type = decltype(&MyCreateHardLinkTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateHardLinkTransactedW(
    lpFileName, lpExistingFileName, lpSecurityAttributes, hTransaction
  );
}

BOOL WINAPI MyCreateHardLinkW(
  LPCWSTR lpFileName,
  LPCWSTR lpExistingFileName,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateHardLinkW);
  using real_type = decltype(&MyCreateHardLinkW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateHardLinkW(lpFileName, lpExistingFileName, lpSecurityAttributes);
}

HANDLE WINAPI MyCreateIoCompletionPort(
  HANDLE FileHandle,
  HANDLE ExistingCompletionPort,
  ULONG_PTR CompletionKey,
  DWORD NumberOfConcurrentThreads
) {
  using func_type = decltype(&CreateIoCompletionPort);
  using real_type = decltype(&MyCreateIoCompletionPort);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateIoCompletionPort(
    FileHandle, ExistingCompletionPort, CompletionKey, NumberOfConcurrentThreads
  );
}

HANDLE WINAPI MyCreateJobObjectA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCSTR lpName
) {
  using func_type = decltype(&CreateJobObjectA);
  using real_type = decltype(&MyCreateJobObjectA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateJobObjectA(lpSecurityAttributes, lpName);
}

HANDLE WINAPI MyCreateJobObjectW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCWSTR lpName
) {
  using func_type = decltype(&CreateJobObjectW);
  using real_type = decltype(&MyCreateJobObjectW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateJobObjectW(lpSecurityAttributes, lpName);
}

HANDLE WINAPI MyCreateMailslotA(
  LPCSTR lpName,
  DWORD nMaxMessageSize,
  DWORD lReadTimeout,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateMailslotA);
  using real_type = decltype(&MyCreateMailslotA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMailslotA(
    lpName, nMaxMessageSize, lReadTimeout, lpSecurityAttributes
  );
}

HANDLE WINAPI MyCreateMailslotW(
  LPCWSTR lpName,
  DWORD nMaxMessageSize,
  DWORD lReadTimeout,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateMailslotW);
  using real_type = decltype(&MyCreateMailslotW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMailslotW(
    lpName, nMaxMessageSize, lReadTimeout, lpSecurityAttributes
  );
}

HANDLE WINAPI MyCreateMemoryResourceNotification(
  MEMORY_RESOURCE_NOTIFICATION_TYPE NotificationType
) {
  using func_type = decltype(&CreateMemoryResourceNotification);
  using real_type = decltype(&MyCreateMemoryResourceNotification);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMemoryResourceNotification(NotificationType);
}

HANDLE WINAPI MyCreateMutexA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  BOOL bInitialOwner,
  LPCSTR lpName
) {
  using func_type = decltype(&CreateMutexA);
  using real_type = decltype(&MyCreateMutexA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMutexA(lpSecurityAttributes, bInitialOwner, lpName);
}

HANDLE WINAPI MyCreateMutexExA(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateMutexExA);
  using real_type = decltype(&MyCreateMutexExA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMutexExA(lpSecurityAttributes, lpName, dwFlags, dwDesiredAccess);
}

HANDLE WINAPI MyCreateMutexExW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateMutexExW);
  using real_type = decltype(&MyCreateMutexExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMutexExW(lpSecurityAttributes, lpName, dwFlags, dwDesiredAccess);
}

HANDLE WINAPI MyCreateMutexW(
  LPSECURITY_ATTRIBUTES lpSecurityAttributes,
  BOOL bInitialOwner,
  LPCWSTR lpName
) {
  using func_type = decltype(&CreateMutexW);
  using real_type = decltype(&MyCreateMutexW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateMutexW(lpSecurityAttributes, bInitialOwner, lpName);
}

HANDLE WINAPI MyCreateNamedPipeA(
  LPCSTR lpName,
  DWORD dwOpenMode,
  DWORD dwPipeMode,
  DWORD nMaxInstances,
  DWORD nOutBufferSize,
  DWORD nInBufferSize,
  DWORD nDefaultTimeOut,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateNamedPipeA);
  using real_type = decltype(&MyCreateNamedPipeA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateNamedPipeA(
    lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize,
    nInBufferSize, nDefaultTimeOut, lpSecurityAttributes
  );
}

HANDLE WINAPI MyCreateNamedPipeW(
  LPCWSTR lpName,
  DWORD dwOpenMode,
  DWORD dwPipeMode,
  DWORD nMaxInstances,
  DWORD nOutBufferSize,
  DWORD nInBufferSize,
  DWORD nDefaultTimeOut,
  LPSECURITY_ATTRIBUTES lpSecurityAttributes
) {
  using func_type = decltype(&CreateNamedPipeW);
  using real_type = decltype(&MyCreateNamedPipeW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateNamedPipeW(
    lpName, dwOpenMode, dwPipeMode, nMaxInstances, nOutBufferSize,
    nInBufferSize, nDefaultTimeOut, lpSecurityAttributes
  );
}

BOOL WINAPI MyCreatePipe(
  PHANDLE hReadPipe,
  PHANDLE hWritePipe,
  LPSECURITY_ATTRIBUTES lpPipeAttributes,
  DWORD nSize
) {
  using func_type = decltype(&CreatePipe);
  using real_type = decltype(&MyCreatePipe);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreatePipe(hReadPipe, hWritePipe, lpPipeAttributes, nSize);
}

HANDLE WINAPI MyCreatePrivateNamespaceA(
  LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes,
  LPVOID lpBoundaryDescriptor,
  LPCSTR lpAliasPrefix
) {
  using func_type = decltype(&CreatePrivateNamespaceA);
  using real_type = decltype(&MyCreatePrivateNamespaceA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreatePrivateNamespaceA(
    lpPrivateNamespaceAttributes, lpBoundaryDescriptor, lpAliasPrefix
  );
}

HANDLE WINAPI MyCreatePrivateNamespaceW(
  LPSECURITY_ATTRIBUTES lpPrivateNamespaceAttributes,
  LPVOID lpBoundaryDescriptor,
  LPCWSTR lpAliasPrefix
) {
  using func_type = decltype(&CreatePrivateNamespaceW);
  using real_type = decltype(&MyCreatePrivateNamespaceW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreatePrivateNamespaceW(
    lpPrivateNamespaceAttributes, lpBoundaryDescriptor, lpAliasPrefix
  );
}

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
) {
  using func_type = decltype(&CreateProcessA);
  using real_type = decltype(&MyCreateProcessA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateProcessA(
    lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
    bInheritHandle, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
    lpStartupInfo, lpProcessInformation
  );
}

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
) {
  using func_type = decltype(&CreateProcessAsUserA);
  using real_type = decltype(&MyCreateProcessAsUserA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateProcessAsUserA(
    hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandle, dwCreationFlags, lpEnvironment,
    lpCurrentDirectory, lpStartupInfo, lpProcessInformation
  );
}

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
) {
  using func_type = decltype(&CreateProcessAsUserW);
  using real_type = decltype(&MyCreateProcessAsUserW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateProcessAsUserW(
    hToken, lpApplicationName, lpCommandLine, lpProcessAttributes,
    lpThreadAttributes, bInheritHandle, dwCreationFlags, lpEnvironment,
    lpCurrentDirectory, lpStartupInfo, lpProcessInformation
  );
}

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
) {
  using func_type = decltype(&CreateProcessW);
  using real_type = decltype(&MyCreateProcessW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateProcessW(
    lpApplicationName, lpCommandLine, lpProcessAttributes, lpThreadAttributes,
    bInheritHandle, dwCreationFlags, lpEnvironment, lpCurrentDirectory,
    lpStartupInfo, lpProcessInformation
  );
}

HRESULT WINAPI MyCreatePseudoConsole(
  COORD size,
  HANDLE hInput,
  HANDLE hOutput,
  DWORD dwFlags,
  HPCON* phPC
) {
  using func_type = decltype(&CreatePseudoConsole);
  using real_type = decltype(&MyCreatePseudoConsole);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreatePseudoConsole(size, hInput, hOutput, dwFlags, phPC);
}

HANDLE WINAPI MyCreateRemoteThread(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAdress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
) {
  using func_type = decltype(&CreateRemoteThread);
  using real_type = decltype(&MyCreateRemoteThread);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateRemoteThread(
    hProcess, lpThreadAttributes, dwStackSize, lpStartAdress, lpParameter,
    dwCreationFlags, lpThreadId
  );
}

HANDLE WINAPI MyCreateRemoteThreadEx(
  HANDLE hProcess,
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList,
  LPDWORD lpThreadId
) {
  using func_type = decltype(&CreateRemoteThreadEx);
  using real_type = decltype(&MyCreateRemoteThreadEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateRemoteThreadEx(
    hProcess, lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
    dwCreationFlags, lpAttributeList, lpThreadId
  );
}

HANDLE WINAPI MyCreateSemaphoreA(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCSTR lpName
) {
  using func_type = decltype(&CreateSemaphoreA);
  using real_type = decltype(&MyCreateSemaphoreA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSemaphoreA(
    lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName
  );
}

HANDLE WINAPI MyCreateSemaphoreExA(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateSemaphoreExA);
  using real_type = decltype(&MyCreateSemaphoreExA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSemaphoreExA(
    lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags,
    dwDesiredAccess
  );
}

HANDLE WINAPI MyCreateSemaphoreExW(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCWSTR lpName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateSemaphoreExW);
  using real_type = decltype(&MyCreateSemaphoreExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSemaphoreExW(
    lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName, dwFlags,
    dwDesiredAccess
  );
}

HANDLE WINAPI MyCreateSemaphoreW(
  LPSECURITY_ATTRIBUTES lpSemaphoreAttributes,
  LONG lInitialCount,
  LONG lMaximumCount,
  LPCWSTR lpName
) {
  using func_type = decltype(&CreateSemaphoreW);
  using real_type = decltype(&MyCreateSemaphoreW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSemaphoreW(
    lpSemaphoreAttributes, lInitialCount, lMaximumCount, lpName
  );
}

BOOLEAN WINAPI MyCreateSymbolicLinkA(
  LPCSTR lpSymlinkFileName,
  LPCSTR lpTargetFileName,
  DWORD dwFlags
) {
  using func_type = decltype(&CreateSymbolicLinkA);
  using real_type = decltype(&MyCreateSymbolicLinkA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSymbolicLinkA(lpSymlinkFileName, lpTargetFileName, dwFlags);
}

BOOLEAN WINAPI MyCreateSymbolicLinkTransactedA(
  LPCSTR lpSymlinkFileName,
  LPCSTR lpTargetFileName,
  DWORD dwFlags,
  HANDLE hTransaction
) {
  using func_type = decltype(&CreateSymbolicLinkTransactedA);
  using real_type = decltype(&MyCreateSymbolicLinkTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSymbolicLinkTransactedA(
    lpSymlinkFileName, lpTargetFileName, dwFlags, hTransaction
  );
}

BOOLEAN WINAPI MyCreateSymbolicLinkTransactedW(
  LPCWSTR lpSymlinkFileName,
  LPCWSTR lpTargetFileName,
  DWORD dwFlags,
  HANDLE hTransaction
) {
  using func_type = decltype(&CreateSymbolicLinkTransactedW);
  using real_type = decltype(&MyCreateSymbolicLinkTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSymbolicLinkTransactedW(
    lpSymlinkFileName, lpTargetFileName, dwFlags, hTransaction
  );
}

BOOLEAN WINAPI MyCreateSymbolicLinkW(
  LPCWSTR lpSymlinkFileName,
  LPCWSTR lpTargetFileName,
  DWORD dwFlags
) {
  using func_type = decltype(&CreateSymbolicLinkW);
  using real_type = decltype(&MyCreateSymbolicLinkW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateSymbolicLinkW(lpSymlinkFileName, lpTargetFileName, dwFlags);
}

DWORD WINAPI MyCreateTapePartition(
  HANDLE hDevice,
  DWORD dwPartitionMethod,
  DWORD dwCount,
  DWORD dwSize
) {
  using func_type = decltype(&CreateTapePartition);
  using real_type = decltype(&MyCreateTapePartition);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateTapePartition(hDevice, dwPartitionMethod, dwCount, dwSize);
}

HANDLE WINAPI MyCreateThread(
  LPSECURITY_ATTRIBUTES lpThreadAttributes,
  SIZE_T dwStackSize,
  LPTHREAD_START_ROUTINE lpStartAddress,
  __drv_aliasesMem LPVOID lpParameter,
  DWORD dwCreationFlags,
  LPDWORD lpThreadId
) {
  using func_type = decltype(&CreateThread);
  using real_type = decltype(&MyCreateThread);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThread(
    lpThreadAttributes, dwStackSize, lpStartAddress, lpParameter,
    dwCreationFlags, lpThreadId
  );
}

PTP_POOL WINAPI MyCreateThreadpool(
  PVOID reserved
) {
  using func_type = decltype(&CreateThreadpool);
  using real_type = decltype(&MyCreateThreadpool);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpool(reserved);
}

PTP_CLEANUP_GROUP WINAPI MyCreateThreadpoolCleanupGroup() {
  using func_type = decltype(&CreateThreadpoolCleanupGroup);
  using real_type = decltype(&MyCreateThreadpoolCleanupGroup);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpoolCleanupGroup();
}

PTP_IO WINAPI MyCreateThreadpoolIo(
  HANDLE fl,
  PTP_WIN32_IO_CALLBACK pfnio,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
) {
  using func_type = decltype(&CreateThreadpoolIo);
  using real_type = decltype(&MyCreateThreadpoolIo);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpoolIo(fl, pfnio, pv, pcbe);
}

PTP_TIMER WINAPI MyCreateThreadpoolTimer(
  PTP_TIMER_CALLBACK pfnti,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
) {
  using func_type = decltype(&CreateThreadpoolTimer);
  using real_type = decltype(&MyCreateThreadpoolTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpoolTimer(pfnti, pv, pcbe);
}

PTP_WAIT WINAPI MyCreateThreadpoolWait(
  PTP_WAIT_CALLBACK pfnwa,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
) {
  using func_type = decltype(&CreateThreadpoolWait);
  using real_type = decltype(&MyCreateThreadpoolWait);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpoolWait(pfnwa, pv, pcbe);
}

PTP_WORK WINAPI MyCreateThreadpoolWork(
  PTP_WORK_CALLBACK pfnwk,
  PVOID pv,
  PTP_CALLBACK_ENVIRON pcbe
) {
  using func_type = decltype(&CreateThreadpoolWork);
  using real_type = decltype(&MyCreateThreadpoolWork);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateThreadpoolWork(pfnwk, pv, pcbe);
}

HANDLE WINAPI MyCreateTimerQueue() {
  using func_type = decltype(&CreateTimerQueue);
  using real_type = decltype(&MyCreateTimerQueue);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateTimerQueue();
}

BOOL WINAPI MyCreateTimerQueueTimer(
  PHANDLE phNewTimer,
  HANDLE TimerQueue,
  WAITORTIMERCALLBACK Callback,
  PVOID Parameter,
  DWORD DueTime,
  DWORD Period,
  ULONG Flags
) {
  using func_type = decltype(&CreateTimerQueueTimer);
  using real_type = decltype(&MyCreateTimerQueueTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateTimerQueueTimer(
    phNewTimer, TimerQueue, Callback, Parameter, DueTime, Period, Flags
  );
}

HANDLE WINAPI MyCreateToolhelp32Snapshot(
  DWORD dwFlags,
  DWORD th32ProcessID
) {
  using func_type = decltype(&CreateToolhelp32Snapshot);
  using real_type = decltype(&MyCreateToolhelp32Snapshot);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateToolhelp32Snapshot(dwFlags, th32ProcessID);
}

BOOL WINAPI MyCreateUmsCompletionList(
  PUMS_COMPLETION_LIST* UmsCompletionList
) {
  using func_type = decltype(&CreateUmsCompletionList);
  using real_type = decltype(&MyCreateUmsCompletionList);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateUmsCompletionList(UmsCompletionList);
}

BOOL WINAPI MyCreateUmsThreadContext(
  PUMS_CONTEXT* lpUmsThread
) {
  using func_type = decltype(&CreateUmsThreadContext);
  using real_type = decltype(&MyCreateUmsThreadContext);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateUmsThreadContext(lpUmsThread);
}

HANDLE WINAPI MyCreateWaitableTimerExW(
  LPSECURITY_ATTRIBUTES lpTimerAttributes,
  LPCWSTR lpTimerName,
  DWORD dwFlags,
  DWORD dwDesiredAccess
) {
  using func_type = decltype(&CreateWaitableTimerExW);
  using real_type = decltype(&MyCreateWaitableTimerExW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateWaitableTimerExW(
    lpTimerAttributes, lpTimerName, dwFlags, dwDesiredAccess
  );
}

HANDLE WINAPI MyCreateWaitableTimerW(
  LPSECURITY_ATTRIBUTES lpTimerAttributes,
  BOOL bManualReset,
  LPCWSTR lpTimerName
) {
  using func_type = decltype(&CreateWaitableTimerW);
  using real_type = decltype(&MyCreateWaitableTimerW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return CreateWaitableTimerW(lpTimerAttributes, bManualReset, lpTimerName);
}

BOOL WINAPI MyDeactivateActCtx(
  DWORD dwFlags,
  ULONG_PTR ulCookie
) {
  using func_type = decltype(&DeactivateActCtx);
  using real_type = decltype(&MyDeactivateActCtx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeactivateActCtx(dwFlags, ulCookie);
}

void WINAPI MyDebugBreak() {
  using func_type = decltype(&DebugBreak);
  using real_type = decltype(&MyDebugBreak);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DebugBreak();
}

BOOL WINAPI MyDebugBreakProcess(
  HANDLE hProcess
) {
  using func_type = decltype(&DebugBreakProcess);
  using real_type = decltype(&MyDebugBreakProcess);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DebugBreakProcess(hProcess);
}

BOOL WINAPI MyDebugSetProcessKillOnExit(
  BOOL KillOnExit
) {
  using func_type = decltype(&DebugSetProcessKillOnExit);
  using real_type = decltype(&MyDebugSetProcessKillOnExit);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DebugSetProcessKillOnExit(KillOnExit);
}

PVOID WINAPI MyDecodePointer(
  PVOID Ptr
) {
  using func_type = decltype(&DecodePointer);
  using real_type = decltype(&MyDecodePointer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DecodePointer(Ptr);
}

PVOID WINAPI MyDecodeSystemPointer(
  PVOID Ptr
) {
  using func_type = decltype(&DecodeSystemPointer);
  using real_type = decltype(&MyDecodeSystemPointer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DecodeSystemPointer(Ptr);
}

BOOL WINAPI MyDefineDosDeviceA(
  DWORD dwFlags,
  LPCSTR lpDeviceName,
  LPCSTR lpTargetPath
) {
  using func_type = decltype(&DefineDosDeviceA);
  using real_type = decltype(&MyDefineDosDeviceA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DefineDosDeviceA(dwFlags, lpDeviceName, lpTargetPath);
}

BOOL WINAPI MyDefineDosDeviceW(
  DWORD dwFlags,
  LPCWSTR lpDeviceName,
  LPCWSTR lpTargetPath
) {
  using func_type = decltype(&DefineDosDeviceW);
  using real_type = decltype(&MyDefineDosDeviceW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DefineDosDeviceW(dwFlags, lpDeviceName, lpTargetPath);
}

ATOM WINAPI MyDeleteAtom(
  ATOM nAtom
) {
  using func_type = decltype(&DeleteAtom);
  using real_type = decltype(&MyDeleteAtom);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteAtom(nAtom);
}

void WINAPI MyDeleteBoundaryDescriptor(
  HANDLE BoundaryDescriptor
) {
  using func_type = decltype(&DeleteBoundaryDescriptor);
  using real_type = decltype(&MyDeleteBoundaryDescriptor);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteBoundaryDescriptor(BoundaryDescriptor);
}

void WINAPI MyDeleteCriticalSection(
  LPCRITICAL_SECTION lpCriticalSection
) {
  using func_type = decltype(&DeleteCriticalSection);
  using real_type = decltype(&MyDeleteCriticalSection);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteCriticalSection(lpCriticalSection);
}

void WINAPI MyDeleteFiber(
  LPVOID lpFiber
) {
  using func_type = decltype(&DeleteFiber);
  using real_type = decltype(&MyDeleteFiber);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteFiber(lpFiber);
}

BOOL WINAPI MyDeleteFileA(
  LPCSTR lpFileName
) {
  using func_type = decltype(&DeleteFileA);
  using real_type = decltype(&MyDeleteFileA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteFileA(lpFileName);
}

BOOL WINAPI MyDeleteFileTransactedA(
  LPCSTR lpFileName,
  HANDLE hTransactoin
) {
  using func_type = decltype(&DeleteFileTransactedA);
  using real_type = decltype(&MyDeleteFileTransactedA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteFileTransactedA(lpFileName, hTransactoin);
}

BOOL WINAPI MyDeleteFileTransactedW(
  LPCWSTR lpFileName,
  HANDLE hTransactoin
) {
  using func_type = decltype(&DeleteFileTransactedW);
  using real_type = decltype(&MyDeleteFileTransactedW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteFileTransactedW(lpFileName, hTransactoin);
}

BOOL WINAPI MyDeleteFileW(
  LPCWSTR lpFileName
) {
  using func_type = decltype(&DeleteFileW);
  using real_type = decltype(&MyDeleteFileW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteFileW(lpFileName);
}

void WINAPI MyDeleteProcThreadAttributeList(
  LPPROC_THREAD_ATTRIBUTE_LIST lpAttributeList
) {
  using func_type = decltype(&DeleteProcThreadAttributeList);
  using real_type = decltype(&MyDeleteProcThreadAttributeList);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteProcThreadAttributeList(lpAttributeList);
}

BOOL WINAPI MyDeleteSynchronizationBarrier(
  LPSYNCHRONIZATION_BARRIER lpBarrier
) {
  using func_type = decltype(&DeleteSynchronizationBarrier);
  using real_type = decltype(&MyDeleteSynchronizationBarrier);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteSynchronizationBarrier(lpBarrier);
}

BOOL WINAPI MyDeleteTimerQueue(
  HANDLE TimerQueue
) {
  using func_type = decltype(&DeleteTimerQueue);
  using real_type = decltype(&MyDeleteTimerQueue);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteTimerQueue(TimerQueue);
}

BOOL WINAPI MyDeleteTimerQueueEx(
  HANDLE TimerQueue,
  HANDLE CompletionEvent
) {
  using func_type = decltype(&DeleteTimerQueueEx);
  using real_type = decltype(&MyDeleteTimerQueueEx);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteTimerQueueEx(TimerQueue, CompletionEvent);
}

BOOL WINAPI MyDeleteTimerQueueTimer(
  HANDLE TimerQueue,
  HANDLE Timer,
  HANDLE CompletionEvent
) {
  using func_type = decltype(&DeleteTimerQueueTimer);
  using real_type = decltype(&MyDeleteTimerQueueTimer);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteTimerQueueTimer(TimerQueue, Timer, CompletionEvent);
}

BOOL WINAPI MyDeleteUmsCompletionList(
  PUMS_COMPLETION_LIST UmsCompletionList
) {
  using func_type = decltype(&DeleteUmsCompletionList);
  using real_type = decltype(&MyDeleteUmsCompletionList);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteUmsCompletionList(UmsCompletionList);
}

BOOL WINAPI MyDeleteUmsThreadContext(
  PUMS_CONTEXT UmsThread
) {
  using func_type = decltype(&DeleteUmsThreadContext);
  using real_type = decltype(&MyDeleteUmsThreadContext);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteUmsThreadContext(UmsThread);
}

BOOL WINAPI MyDeleteVolumeMountPointA(
  LPCSTR lpszVolumeMountPoint
) {
  using func_type = decltype(&DeleteVolumeMountPointA);
  using real_type = decltype(&MyDeleteVolumeMountPointA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteVolumeMountPointA(lpszVolumeMountPoint);
}

BOOL WINAPI MyDeleteVolumeMountPointW(
  LPCWSTR lpszVolumeMountPoint
) {
  using func_type = decltype(&DeleteVolumeMountPointW);
  using real_type = decltype(&MyDeleteVolumeMountPointW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeleteVolumeMountPointW(lpszVolumeMountPoint);
}

BOOL WINAPI MyDequeueUmsCompletionListItems(
  PUMS_COMPLETION_LIST UmsCompletionContext,
  DWORD WaitTime,
  PUMS_CONTEXT* UmsThreadList
) {
  using func_type = decltype(&DequeueUmsCompletionListItems);
  using real_type = decltype(&MyDequeueUmsCompletionListItems);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DequeueUmsCompletionListItems(
    UmsCompletionContext, WaitTime, UmsThreadList
  );
}

BOOL WINAPI MyDeviceIoControl(
  HANDLE hDevice,
  DWORD dwIoControlCode,
  LPVOID lpInBuffer,
  DWORD nInBufferSize,
  LPVOID lpOutBuffer,
  DWORD nOutBufferSize,
  LPDWORD lpBytesReturned,
  LPOVERLAPPED lpOverlapped
) {
  using func_type = decltype(&DeviceIoControl);
  using real_type = decltype(&MyDeviceIoControl);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DeviceIoControl(
    hDevice, dwIoControlCode, lpInBuffer, nInBufferSize, lpOutBuffer,
    nOutBufferSize, lpBytesReturned, lpOverlapped
  );
}

BOOL WINAPI MyDisableThreadLibraryCalls(
  HMODULE hLibModule
) {
  using func_type = decltype(&DisableThreadLibraryCalls);
  using real_type = decltype(&MyDisableThreadLibraryCalls);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DisableThreadLibraryCalls(hLibModule);
}

DWORD WINAPI MyDisableThreadProfiling(
  HANDLE PerformanceDataHandle
) {
  using func_type = decltype(&DisableThreadProfiling);
  using real_type = decltype(&MyDisableThreadProfiling);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DisableThreadProfiling(PerformanceDataHandle);
}

void WINAPI MyDisassociateCurrentThreadFromCallback(
  PTP_CALLBACK_INSTANCE pci
) {
  using func_type = decltype(&DisassociateCurrentThreadFromCallback);
  using real_type = decltype(&MyDisassociateCurrentThreadFromCallback);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DisassociateCurrentThreadFromCallback(pci);
}

DWORD WINAPI MyDiscardVirtualMemory(
  PVOID VirtualAddress,
  SIZE_T Size
) {
  using func_type = decltype(&DiscardVirtualMemory);
  using real_type = decltype(&MyDiscardVirtualMemory);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }

  return DiscardVirtualMemory(VirtualAddress, Size);
}

/// Here

HANDLE WINAPI MyFindFirstFileA(
  LPCSTR lpFileName,
  LPWIN32_FIND_DATAA lpFindFileData
) {
  using func_type = decltype(&FindFirstFileA);
  using real_type = decltype(&MyFindFirstFileA);

  static_assert(std::is_same_v<real_type, func_type>);

  using func_next_type = decltype(&FindNextFileA);
  using func_close_type = decltype(&FindClose);

  static const std::string funcFirstName(__func__ + 2);
  static const std::string funcNextName("FindNextFileA");
  static const std::string funcCloseName("FindClose");
  
  HANDLE hFile = INVALID_HANDLE_VALUE;

  static auto baseFirstFuncAddr = _funcMap[funcFirstName];
  if (baseFirstFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_type baseFirstFunc = reinterpret_cast<func_type>(baseFirstFuncAddr);

  static auto baseNextFuncAddr = _funcMap[funcNextName];
  if (baseNextFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_next_type baseNextFunc =
    reinterpret_cast<func_next_type>(baseNextFuncAddr);
  
  static auto baseCloseFuncAddr = _funcMap[funcCloseName];
  if (baseCloseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_close_type baseCloseFunc =
    reinterpret_cast<func_close_type>(baseCloseFuncAddr);

  if (_track._funcNames.count(funcFirstName)
    && _track._funcNames[funcFirstName]) {
    _SendInfo(funcFirstName);
  }

  hFile = baseFirstFunc(lpFileName, lpFindFileData);
  if (hFile == INVALID_HANDLE_VALUE) { return hFile; }

  BOOL bFound = _CheckA(lpFindFileData->cFileName);

  // If this filename should not be hidden
  if (!bFound) { return hFile; }

  // This file filename should be hidden so iterate over found files
  
  BOOL bRes = TRUE;

  while (baseNextFunc(hFile, lpFindFileData)) {
    // If this filename shouldn't be hidden return
    if (!_CheckA(lpFindFileData->cFileName)) { return hFile; }
  }

  // All files are hidden
  baseCloseFunc(hFile);
  std::memset(lpFindFileData, 0x00, sizeof(*lpFindFileData));
  SetLastError(ERROR_FILE_NOT_FOUND);

  return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI MyFindFirstFileW(
  LPCWSTR lpFileName,
  LPWIN32_FIND_DATAW lpFindFileData
) {
  using func_type = decltype(&FindFirstFileW);
  using real_type = decltype(&MyFindFirstFileW);

  static_assert(std::is_same_v<real_type, func_type>);

  using func_next_type = decltype(&FindNextFileW);
  using func_close_type = decltype(&FindClose);

  static const std::string funcFirstName(__func__ + 2);
  static const std::string funcNextName("FindNextFileW");
  static const std::string funcCloseName("FindClose");
  
  HANDLE hFile = INVALID_HANDLE_VALUE;

  static auto baseFirstFuncAddr = _funcMap[funcFirstName];
  if (baseFirstFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_type baseFirstFunc = reinterpret_cast<func_type>(baseFirstFuncAddr);

  static auto baseNextFuncAddr = _funcMap[funcNextName];
  if (baseNextFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_next_type baseNextFunc =
    reinterpret_cast<func_next_type>(baseNextFuncAddr);
  
  static auto baseCloseFuncAddr = _funcMap[funcCloseName];
  if (baseCloseFuncAddr == NULL) { return INVALID_HANDLE_VALUE; }

  func_close_type baseCloseFunc =
    reinterpret_cast<func_close_type>(baseCloseFuncAddr);

  if (_track._funcNames.count(funcFirstName)
    && _track._funcNames[funcFirstName]) {
    _SendInfo(funcFirstName);
  }

  hFile = baseFirstFunc(lpFileName, lpFindFileData);
  if (hFile == INVALID_HANDLE_VALUE) { return hFile; }

  BOOL bFound = _CheckW(lpFindFileData->cFileName);

  // If this filename should not be hidden
  if (!bFound) { return hFile; }

  // This file filename should be hidden so iterate over found files
  
  BOOL bRes = TRUE;

  while (baseNextFunc(hFile, lpFindFileData)) {
    // If this filename shouldn't be hidden return
    if (!_CheckW(lpFindFileData->cFileName)) { return hFile; }
  }

  // All files are hidden
  baseCloseFunc(hFile);
  std::memset(lpFindFileData, 0x00, sizeof(*lpFindFileData));
  SetLastError(ERROR_FILE_NOT_FOUND);

  return INVALID_HANDLE_VALUE;
}

BOOL WINAPI MyFindNextFileA(
  HANDLE hFindFile,
  LPWIN32_FIND_DATAA lpFindFileData
) {
  using func_type = decltype(&FindNextFileA);
  using real_type = decltype(&MyFindNextFileA);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }
  
  BOOL bRes = TRUE;
  while (FindNextFileA(hFindFile, lpFindFileData)) {
    if (!_CheckA(lpFindFileData->cFileName)) { return TRUE; }
  }

  return FALSE;
}
BOOL WINAPI MyFindNextFileW(
  HANDLE hFindFile,
  LPWIN32_FIND_DATAW lpFindFileData
) {
  using func_type = decltype(&FindNextFileW);
  using real_type = decltype(&MyFindNextFileW);

  static_assert(std::is_same_v<real_type, func_type>);

  static const std::string funcName(__func__ + 2);
  
  if (_track._funcNames.count(funcName) && _track._funcNames[funcName]) {
    _SendInfo(funcName);
  }
  
  BOOL bRes = TRUE;
  while (FindNextFileW(hFindFile, lpFindFileData)) {
    if (!_CheckW(lpFindFileData->cFileName)) { return TRUE; }
  }

  return FALSE;
}

BOOL _CheckA(LPCSTR lpFileName) {
  BOOL bFound = FALSE;

  for (const auto& el : _track._hideFilenamesA) {
    if (!el.compare(lpFileName))  {
      bFound = TRUE;
      break;
    }
  }
  return bFound;
}

BOOL _CheckW(LPCWSTR lpFileName) {
  BOOL bFound = FALSE;

  for (const auto& el : _track._hideFilenamesW) {
    if (!el.compare(lpFileName))  {
      bFound = TRUE;
      break;
    }
  }
  return bFound;
}
