# define NTDDI_VERSION NTDDI_VISTA
# undef _WIN32_WINNT
# define _WIN32_WINNT _WIN32_WINNT_VISTA

#include <iostream>
#include <string>
#include <easyhook.h>
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <psapi.h>
#include <ioapiset.h>
#include <strsafe.h>

#include "../include/shared.h"
#include "monitor.h"

#pragma comment(lib, "advapi32.lib")

#define _CRT_SECURE_NO_WARNINGS
#ifdef NDEBUG
#define DLL_PATH_X64 L"..\\x64\\Release\\showlibs.dll"
#else
#define DLL_PATH_X64 L"..\\x64\\Debug\\showlibs.dll"
#endif

MyProgram::
Monitor::Monitor(const std::vector<std::string>& __args) {
  enum { PID, FUNC, HIDE };

  std::vector<std::string> __command = __args;
  std::vector<DWORD> __currPids;
  DWORD __mode = -1;
  while (!__command.empty()
    && __command.front().compare("-pid")
    && __command.front().compare("-name")) {
    __command.erase(__command.begin());
  }
  
  while (!__command.empty()) {
    auto __elem = __command.front();
    if (!__elem.compare("-pid") || !__elem.compare("-name")) {
      __mode = PID;
    } else if (!__currPids.empty() && !__elem.compare("-func")) {
      __mode = FUNC;
    } else if (!__currPids.empty() && !__elem.compare("-hide")) {
      __mode = HIDE;
    } else if (__mode == PID) { __currPids = _AddProc(__elem); }
    else if (__mode == FUNC) { _AddFunc(__currPids, __elem); }
    else if (__mode == HIDE) { _AddFilename(__currPids, __elem); }
    __command.erase(__command.begin());
  }

  for (const auto& __proc : _pidToTrackingInfo) {
    if (!__proc.second._hideFilenamesA.empty()
      || !__proc.second._hideFilenamesW.empty()
    ) {
      _AddImplFuncs(__proc.first);
    }
  }
}

void
MyProgram::
Monitor::Run() {
  _CreatePipes();
  _ConnectToAllClients();
  _InjectLibAll();
  _ServerOperate();
}

void
MyProgram::
Monitor::Print() {
  for (const auto& __el : _pidToTrackingInfo) {
    std::cout << "Process id: " << __el.first << " Process name: "
      << _pidToProcName[__el.first] << "\n\tFunctions:\n";
    for (const auto& __name : __el.second._funcNames) {
      std::cout << "\t\t" << __name.first << " Verbose: "
        << ((__name.second) ? "True" : "False") << '\n';
    }
    std::cout << "\tHideA:\n";
    for (const auto& __name : __el.second._hideFilenamesA) {
      std::cout << "\t\t" << __name << '\n';
    }
    std::cout << "\tHideW:\n";
    for (const auto& __name : __el.second._hideFilenamesW) {
      std::wcout << "\t\t" << __name << '\n';
    }
  }
}

std::vector<DWORD>
MyProgram::
Monitor::_AddProc(const std::string& __procStr) {
  std::vector<DWORD> __pids;
  std::string __procName("Not found");
  try {
    DWORD __pid = std::stoi(__procStr);
    __pids.push_back(__pid);
  }
  catch (...) {}

  if (__pids.empty()) {
    __pids = _GetProcIdsByName(__procStr);
    __procName = __procStr;
  } else {
    HANDLE __hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, __pids[0]);
    if (__hProcess != NULL) {
      char __procNameBuff[MAX_PATH];
      GetProcessImageFileNameA(__hProcess, __procNameBuff, MAX_PATH);
      __procName = __procNameBuff;
      CloseHandle(__hProcess);
      size_t pos = __procName.rfind('\\');
      if (pos != std::wstring::npos) { __procName.assign(__procName, pos + 1); }
    }
  }

  for (DWORD __pid : __pids) {
    if (__pid != 0 && !_pidToTrackingInfo.count(__pid)) {
      _pidToTrackingInfo[__pid] = TRACKING();
      _pidToProcName[__pid] = __procName;
    }
  }
  
  return __pids;
}

std::vector<DWORD>
MyProgram::
Monitor::_GetProcIdsByName(const std::string& __pidStr) {
  std::vector<DWORD> __pids;
  
  HANDLE __snapProc = NULL;
  PROCESSENTRY32 __pe32;

  __snapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (__snapProc == INVALID_HANDLE_VALUE) { return __pids; }
  
  __pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(__snapProc, &__pe32)) {
    CloseHandle(__snapProc);
    return __pids;
  }

  do {
    if (!__pidStr.compare(__pe32.szExeFile)) {
      __pids.push_back(__pe32.th32ProcessID);
    }
  } while (Process32Next(__snapProc, &__pe32));

  CloseHandle(__snapProc);
  return __pids;
}

void
MyProgram::
Monitor::_AddImplFuncs(DWORD __pid) {
  for (const auto& __funcName : _hideFuncNames) {
    _pidToTrackingInfo[__pid]._funcNames.try_emplace(__funcName, FALSE);
  }
}

void
MyProgram::
Monitor::_AddFunc(
    const std::vector<DWORD>& __pids,
    const std::string& __funcName
) {
  for (DWORD __pid : __pids) {
    if (__pid != 0 && _pidToTrackingInfo.count(__pid)) {
      _pidToTrackingInfo[__pid]._funcNames.emplace(__funcName, TRUE);
    }
  }
}

void
MyProgram::
Monitor::_AddFilename(
  const std::vector<DWORD>& __pids,
  const std::string& __filename
) {
  for (DWORD __pid : __pids) {
    if (__pid != 0 && _pidToTrackingInfo.count(__pid)) {
      _pidToTrackingInfo[__pid]._hideFilenamesA.push_back(__filename);
      std::wstring __tmpStr;
      __tmpStr.reserve(__filename.size());
      for (const auto& __el : _pidToTrackingInfo[__pid]._hideFilenamesA.back()) {
        __tmpStr += WCHAR(__el);
      }
      _pidToTrackingInfo[__pid]._hideFilenamesW.push_back(std::move(__tmpStr));
    }
  }
}

BOOL
MyProgram::
Monitor::_CreatePipes() {
  BOOL __connected = FALSE;
  BOOL __bRes = FALSE;
  DWORD __dwRes = ERROR_SUCCESS;
  PSID __pEveryoneSID = NULL;
  PSID __pAdminSID = NULL;
  PACL __pACL = NULL;
  PSECURITY_DESCRIPTOR __pSD = NULL;
  EXPLICIT_ACCESSA __ea[2];
  SID_IDENTIFIER_AUTHORITY __SIDAuthAll = SECURITY_WORLD_SID_AUTHORITY;
  SID_IDENTIFIER_AUTHORITY __SIDAuthNT = SECURITY_NT_AUTHORITY;
  SECURITY_ATTRIBUTES __sa{0, NULL, FALSE};
  HANDLE __tmpEvent = NULL;
  HANDLE __tmpPipe = INVALID_HANDLE_VALUE;
  PIPEINST __tmpPipeInst{};

  __bRes = AllocateAndInitializeSid(
    &__SIDAuthAll, 1, SECURITY_WORLD_RID, 0, 0, 0, 0, 0, 0, 0, &__pEveryoneSID
  );
  if (!__bRes) { goto Cleanup; }

  __bRes = AllocateAndInitializeSid(
    &__SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS,
    0, 0, 0, 0, 0, 0, &__pAdminSID
  );
  if (!__bRes) { goto Cleanup; }

  ZeroMemory(&__ea, 2 * sizeof(EXPLICIT_ACCESS));

  __ea[0].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
  __ea[0].grfAccessMode = SET_ACCESS;
  __ea[0].grfInheritance = NO_INHERITANCE;
  __ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  __ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  __ea[0].Trustee.ptstrName = reinterpret_cast<LPCH>(__pEveryoneSID);
  
  __ea[1].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
  __ea[1].grfAccessMode = SET_ACCESS;
  __ea[1].grfInheritance = NO_INHERITANCE;
  __ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  __ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  __ea[1].Trustee.ptstrName = reinterpret_cast<LPCH>(__pAdminSID);

  __dwRes = SetEntriesInAclA(2, __ea, NULL, &__pACL);
  if (__dwRes != ERROR_SUCCESS) { goto Cleanup; }

  __pSD = reinterpret_cast<PSECURITY_DESCRIPTOR>(
    LocalAlloc(LPTR, SECURITY_DESCRIPTOR_MIN_LENGTH)
  );
  if (__pSD == NULL) { goto Cleanup; }
  
  __bRes = InitializeSecurityDescriptor(__pSD, SECURITY_DESCRIPTOR_REVISION);
  if (!__bRes) { goto Cleanup; }

  __bRes = SetSecurityDescriptorDacl(__pSD, TRUE, __pACL, FALSE);
  if (!__bRes) { goto Cleanup; }

  __sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  __sa.lpSecurityDescriptor = __pSD;
  __sa.bInheritHandle = FALSE;

  _pipes.reserve(_pidToTrackingInfo.size());
  _events.reserve(_pidToTrackingInfo.size());

  for (const auto& __el : _pidToTrackingInfo) {
    __tmpEvent = CreateEventA(&__sa, TRUE, FALSE, NULL);
    if (__tmpEvent == NULL) {
      std::cout << "CreateEvent failed with: " << GetLastError() << '\n';
      goto Cleanup;
    }

    std::string __pipeName(PIPE_NAME);
    __pipeName += std::to_string(__el.first);

    __tmpPipe = CreateNamedPipeA(
      __pipeName.data(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      PIPE_BUFFER_SIZE,
      PIPE_BUFFER_SIZE,
      PIPE_TIMEOUT,
      &__sa
    );

    if (__tmpPipe == INVALID_HANDLE_VALUE) {
      std::cout << "CreateNamedPipe failed with: " << std::hex
        << GetLastError() << '\n';
      goto Cleanup;
    } else {
      std::cout << "Named pipe sucessfully created for PID: "
        << __el.first << '\n';
    }

    __tmpPipeInst._overlap.Offset = 0;
    __tmpPipeInst._overlap.OffsetHigh = 0;
    __tmpPipeInst._overlap.hEvent = __tmpEvent;
    __tmpPipeInst._pipe = __tmpPipe;
    __tmpPipeInst._pid = __el.first;

    _events.push_back(__tmpEvent);
    _pipes.push_back(__tmpPipeInst);
  }

  return TRUE;
  
Cleanup:
  if (__pEveryoneSID) { FreeSid(__pEveryoneSID); }
  if (__pAdminSID) { FreeSid(__pAdminSID); }
  if (__pACL) { LocalFree(__pACL); }
  if (__pSD) { LocalFree(__pSD); }

  return FALSE;
}

void
MyProgram::
Monitor::_ConnectToAllClients() {
  for (auto& __el : _pipes) {
    __el._pendingIO = _ConnectToNewClient(__el._pipe, &__el._overlap);

    __el._state = __el._pendingIO ? CONNECTING_STATE : OPERATING_STATE;
  }
}

BOOL
MyProgram::
Monitor::_ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped) {
  BOOL __connected = FALSE;
  BOOL __pendingIO = FALSE;

  __connected = ConnectNamedPipe(__pipe, __lpOverlapped);
  if (__connected) {
    std::cout << "ConnectNamedPipe failed with: " << std::hex
      << GetLastError() << '\n';
    return FALSE;
  }

  DWORD __err = GetLastError();

  switch (__err) {
    case ERROR_IO_PENDING:
      __pendingIO = TRUE;
      break;
    case ERROR_PIPE_CONNECTED:
      if (SetEvent(__lpOverlapped->hEvent)) { break; }
      else {
        __err = GetLastError();
        std::cout << "SetEvent failed with: " << std::hex << __err
          << '\n';
        return FALSE;
      }
    default: {
      __err = GetLastError();
      std::cout << "ConnectNamedPipe failed with: " << std::hex << __err
        << '\n';
      return FALSE;
    }
  }
  return __pendingIO;
}

BOOL
MyProgram::
Monitor::_InjectLibAll() {
  for (const auto& __el : _pidToTrackingInfo) {
    if (!_InjectLibByPid(__el.first, DLL_PATH_X64)) {
      std::cout << "Hooking library injection failed for PID: "
        << __el.first << '\n';
    }
    else {
      std::cout << "Hooking library injection success for PID: "
        << __el.first << '\n';
    }
  }
}

BOOL
MyProgram::
Monitor::_InjectLibByPid(DWORD __pid, const std::wstring& __injLib) {

  DWORD __type = INJECT_DLL;
  NTSTATUS __res = 0;
  __res = RhInjectLibrary(
    __pid,
    0,
    EASYHOOK_INJECT_DEFAULT,
    NULL,
    const_cast<WCHAR*>(__injLib.data()),
    &__type,
    sizeof(__type)
  );

  if (__res != 0) {
    PWCHAR __err = RtlGetLastErrorString();
    std::wcout << __err << '\n';
    return FALSE;
  }
  return TRUE;
}

void
MyProgram::
Monitor::_Disconnect(DWORD __idx) {
  BOOL __res;
  __res = DisconnectNamedPipe(_pipes[__idx]._pipe);
 if (!__res) {
    std::cout << "DisconnectNamedPipe failed with: " << GetLastError() << '\n';
 }
 else {
   ResetEvent(_events[__idx]);
  _pipes[__idx]._state = DISCONNECTED_STATE;
   std::cout << "Disconnected PID: " << _pipes[__idx]._pid << '\n';
 }
}

BOOL
MyProgram::
Monitor::_AllDisconnected() {
  for (auto& __el : _pipes) {
    if (__el._state != DISCONNECTED_STATE) { return FALSE; }
  }

  return TRUE;
}

void
MyProgram::Monitor::_ServerOperate() {

  DWORD __wait = 0;
  DWORD __cbRet = 0;
  DWORD __err = ERROR_SUCCESS;
  BOOL __success = TRUE;
  BOOL __operate = TRUE;

  while (__operate) {
    __wait = WaitForMultipleObjects(
      DWORD(_events.size()),
      _events.data(),
      FALSE,
      INFINITE
    );

    DWORD __idx = __wait - WAIT_OBJECT_0;
    if (__idx < 0 || size_t(__idx) + 1 > _events.size()) {
      std::cout << "Index out of range: " << __idx << '\n';
      return;
    }

    if (_pipes[__idx]._pendingIO) {
      __success = GetOverlappedResult(
        _pipes[__idx]._pipe,
        &_pipes[__idx]._overlap,
        &__cbRet,
        FALSE
      );

      switch (_pipes[__idx]._state) {
        case CONNECTING_STATE:
          if (!__success) {
            std::cout << "Error: " << GetLastError() << '\n';
            return;
          }

          __success = _SendInit(__idx);
          if (!__success) {
            _Disconnect(__idx);
            __operate = !_AllDisconnected();
            continue;
          }

          _pipes[__idx]._state = OPERATING_STATE;
          break;

        case OPERATING_STATE:
          if (!__success || __cbRet == 0) {
            _Disconnect(__idx);
            __operate = !_AllDisconnected();
            continue;
          }

          _pipes[__idx]._cbRead = __cbRet;
          if (__success && _pipes[__idx]._cbRead != 0) {
            _pipes[__idx]._pendingIO = FALSE;
            std::cout << _pipes[__idx]._reqBuff << '\n';
          }

          break;
        case DISCONNECTED_STATE:
          break;
        default: {
          std::cout << "Invalid pipe state" << '\n';
          return; 
        }
      }
    }

    switch (_pipes[__idx]._state) {
      case OPERATING_STATE:
        __success = ReadFile(
          _pipes[__idx]._pipe,
          _pipes[__idx]._reqBuff,
          PIPE_BUFFER_SIZE,
          &_pipes[__idx]._cbRead,
          &_pipes[__idx]._overlap
        );

        if (__success && _pipes[__idx]._cbRead != 0) {
          _pipes[__idx]._pendingIO = FALSE;
          std::cout << _pipes[__idx]._reqBuff << '\n';
          continue;
        }

        __err = GetLastError();
        if (!__success && __err == ERROR_IO_PENDING) {
          _pipes[__idx]._pendingIO = TRUE;
          continue;
        }
        _Disconnect(__idx);
        __operate = !_AllDisconnected();
        break;
      case DISCONNECTED_STATE:
        break;
      default: {
        std::cout << "Invalid pipe mode" << '\n';
        return;
      }
    }
  }
}

BOOL
MyProgram::
Monitor::_SendInit(DWORD __idx) {
  DWORD __size = 0;
  DWORD __cbWritten = 0;
  BOOL __success = FALSE;

  // Func names
  const std::unordered_map<std::string, BOOL>& __funcNames =
    _pidToTrackingInfo[_pipes[__idx]._pid]._funcNames;

  __size = DWORD(__funcNames.size());
  __success = WriteFile(
    _pipes[__idx]._pipe,
    &__size,
    sizeof(DWORD),
    &__cbWritten,
    NULL
  );

  if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }
  
  for (const auto& __el : __funcNames) {
    DWORD __strLen = DWORD(__el.first.length());

    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__strLen,
      sizeof(DWORD),
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }

    __success = WriteFile(
      _pipes[__idx]._pipe,
      __el.first.data(),
      __strLen,
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != __strLen) { return __success; }

    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__el.second,
      sizeof(BOOL),
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != sizeof(BOOL)) { return __success; }
  }

  // Hide names
  const std::vector<std::string>& __hideFilenamesA =
    _pidToTrackingInfo[_pipes[__idx]._pid]._hideFilenamesA;

  __size = DWORD(__hideFilenamesA.size());
  __success = WriteFile(
    _pipes[__idx]._pipe,
    &__size,
    sizeof(DWORD),
    &__cbWritten,
    NULL
  );

  if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }
  
  for (const auto& __str : __hideFilenamesA) {
    DWORD __strLen = DWORD(__str.length());
    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__strLen,
      sizeof(DWORD),
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }

    __success = WriteFile(
      _pipes[__idx]._pipe,
      __str.data(),
      __strLen,
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != __strLen) {
      return __success;
    }
  }

  const std::vector<std::wstring>& __hideFilenamesW =
    _pidToTrackingInfo[_pipes[__idx]._pid]._hideFilenamesW;

  __size = DWORD(__hideFilenamesW.size());
  __success = WriteFile(
    _pipes[__idx]._pipe,
    &__size,
    sizeof(DWORD),
    &__cbWritten,
    NULL
  );

  if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }
  
  for (const auto& __str : __hideFilenamesW) {
    DWORD __strLen = DWORD(__str.length());
    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__strLen,
      sizeof(DWORD),
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }

    __success = WriteFile(
      _pipes[__idx]._pipe,
      __str.data(),
      __strLen * sizeof(WCHAR),
      &__cbWritten,
      NULL
    );
    if (!__success && __cbWritten != __strLen * sizeof(WCHAR)) {
      return __success;
    }
  }

  return __success;
}