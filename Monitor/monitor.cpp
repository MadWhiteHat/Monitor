#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>
#include <strsafe.h>

#include "../include/shared.h"
#include "monitor.h"

#pragma comment(lib, "advapi32.lib")

#define _CRT_SECURE_NNO_WARNINGS

void
MyProgram::
Monitor::Run() {
  this->_CreateThreadedPipes();
}

MyProgram::
Monitor::Monitor(const std::vector<std::tstring>& __args) {
  enum { PID, FUNC, HIDE };

  std::vector<std::tstring> __command = __args;
  DWORD __currPid = -1;
  DWORD __mode = -1;
  while (!__command.empty()
    && __command.front().compare(TEXT("-pid"))
    && __command.front().compare(TEXT("-name"))) {
    __command.erase(__command.begin());
  }
  
  while (!__command.empty()) {
    auto __elem = __command.front();
    if (!__elem.compare(TEXT("-pid")) || !__elem.compare(TEXT("-name"))) {
      __mode = PID;
    } else if (__currPid != -1 && !__elem.compare(TEXT("-func"))) {
      __mode = FUNC;
    } else if (__currPid != -1 && !__elem.compare(TEXT("-hide"))) {
      __mode = HIDE;
    } else if (__mode == PID) { __currPid = this->_AddPid(__elem); }
    else if (__mode == FUNC) { this->_AddFunc(__currPid, __elem); }
    else if (__mode == HIDE) { this->_AddFilename(__currPid, __elem); }
    __command.erase(__command.begin());
  }
  _pipes.resize(_mp.size());
  _events.resize(_mp.size());
}

bool
MyProgram::
Monitor::_InjectPid(DWORD __pid, const std::tstring& __injLib) {
  using value_type = typename std::tstring::value_type;
    HANDLE __hProc = NULL;
    __hProc = OpenProcess(
      PROCESS_CREATE_THREAD         // CreateRemoteThread
      | PROCESS_VM_WRITE            // VirtualAllocEx/VirtualFreeEx 
      | PROCESS_VM_OPERATION,       // WriteProcessMemory
      FALSE, __pid);
    if (__hProc == NULL) {
      std::tout << TEXT("Cannot open process") << std::endl;
      return false;
    }
    LPTSTR __libFileRemote = NULL;
    __libFileRemote = reinterpret_cast<LPTSTR>(
      VirtualAllocEx(__hProc, NULL, __injLib.size() * sizeof(value_type),
        MEM_COMMIT, PAGE_READWRITE));
    if (__libFileRemote == NULL) {
      std::tout << TEXT("Cannot allocate memory at remote process") << std::endl;
      CloseHandle(__hProc);
      return false;
    }
    if (!WriteProcessMemory(__hProc, __libFileRemote,
      reinterpret_cast<LPCVOID>(__injLib.data()),
      __injLib.size() * sizeof(value_type), NULL)) {

      std::tout << TEXT("Cannot write process memory") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
      return false;
    }

    HMODULE __kernel = GetModuleHandle(TEXT("kernel32.dll"));
    if (__kernel == NULL) {
      std::tout << TEXT("Cannot obtain kernel handle") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
      return false;
    }

    PTHREAD_START_ROUTINE __threadRoutine =
      reinterpret_cast<PTHREAD_START_ROUTINE>(GetProcAddress(__kernel,
#ifdef _UNICODE
        "LoadLibraryW"
#else
        "LoadLibraryA"
#endif
    ));
    if (__threadRoutine == NULL) {
      std::tout << TEXT("Cannot obtain LoadLibrary address") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
      return false;
    }
    
    HANDLE __remoteThread = NULL;
    __remoteThread = CreateRemoteThread(__hProc, NULL, 0, __threadRoutine,
      __libFileRemote, 0, NULL);
    if (__remoteThread == NULL) {
      std::tout << TEXT("Cannot create remote thread") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
      return false;
    }

    WaitForSingleObject(__remoteThread, INFINITE);

    VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
    CloseHandle(__remoteThread);
    CloseHandle(__hProc);
    return true;
}

bool
MyProgram::
Monitor::_InjectAll(const std::tstring& __injLib) {
  bool __res = true;
  for (const auto& __el : _mp) {
    __res &= this->_InjectPid(__el.first, __injLib);
  }
  return __res;
}

DWORD
MyProgram::
Monitor::_AddPid(const std::tstring& __pidStr) {
  DWORD __pid = 0;
  try { __pid = std::stoi(__pidStr); }
  catch (...) {}

  if (__pid == 0) { __pid = this->_GetProcIdByName(__pidStr); }
  if (__pid != 0 && !_mp.count(__pid)) { _mp[__pid] = Tracking(); }
  
  return (__pid == 0) ? -1 : __pid;
}

DWORD
MyProgram::
Monitor::_GetProcIdByName(const std::tstring& __pidStr) {
  DWORD __pid = 0;

  HANDLE __snapProc = NULL;
  PROCESSENTRY32 __pe32;

  __snapProc = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (__snapProc == INVALID_HANDLE_VALUE) { return __pid; }
  
  __pe32.dwSize = sizeof(PROCESSENTRY32);
  if (!Process32First(__snapProc, &__pe32)) {
    CloseHandle(__snapProc);
    return __pid;
  }

  do {
    if (!__pidStr.compare(__pe32.szExeFile)) {
      __pid = __pe32.th32ProcessID;
      break;
    }
  } while (Process32Next(__snapProc, &__pe32));

  CloseHandle(__snapProc);
  return __pid;
}

void
MyProgram::
Monitor::_AddFunc(DWORD __pid, const std::tstring& __funcName) {
  _mp[__pid]._funcNames.push_back(__funcName);
}

void
MyProgram::
Monitor::_AddFilename(DWORD __pid, const std::tstring& __filename) {
  _mp[__pid]._hideFilenames.push_back(__filename);
}

void
MyProgram::
Monitor::_CreateThreadedPipes() {
  BOOL __connected = FALSE;

  PSID __pEveryoneSID = NULL;
  PSID __pAdminSID = NULL;
  PACL __pACL = NULL;
  PSECURITY_DESCRIPTOR __pSD = NULL;
  EXPLICIT_ACCESS __ea[2];
  SID_IDENTIFIER_AUTHORITY __SIDAuthAll = SECURITY_WORLD_SID_AUTHORITY;
  SID_IDENTIFIER_AUTHORITY __SIDAuthNT = SECURITY_NT_AUTHORITY;
  SECURITY_ATTRIBUTES __sa;
  DWORD i = -1;

  if (!AllocateAndInitializeSid(&__SIDAuthAll, 1, SECURITY_WORLD_RID, 0, 0, 0,
    0, 0, 0, 0, &__pEveryoneSID)) { goto Cleanup; }
  ZeroMemory(&__ea, 2 * sizeof(EXPLICIT_ACCESS));

  __ea[0].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
  __ea[0].grfAccessMode = SET_ACCESS;
  __ea[0].grfInheritance = NO_INHERITANCE;
  __ea[0].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  __ea[0].Trustee.TrusteeType = TRUSTEE_IS_WELL_KNOWN_GROUP;
  __ea[0].Trustee.ptstrName = reinterpret_cast<LPTCH>(__pEveryoneSID);

  if (!AllocateAndInitializeSid(&__SIDAuthNT, 2, SECURITY_BUILTIN_DOMAIN_RID,
    DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &__pAdminSID)) {
    goto Cleanup;
  }
  
  __ea[1].grfAccessPermissions = FILE_GENERIC_READ | FILE_GENERIC_WRITE;
  __ea[1].grfAccessMode = SET_ACCESS;
  __ea[1].grfInheritance = NO_INHERITANCE;
  __ea[1].Trustee.TrusteeForm = TRUSTEE_IS_SID;
  __ea[1].Trustee.TrusteeType = TRUSTEE_IS_GROUP;
  __ea[1].Trustee.ptstrName = reinterpret_cast<LPTCH>(__pAdminSID);

  if (SetEntriesInAcl(2, __ea, NULL, &__pACL) != ERROR_SUCCESS) {
    goto Cleanup;
  }

  __pSD = reinterpret_cast<PSECURITY_DESCRIPTOR>(LocalAlloc(LPTR,
    SECURITY_DESCRIPTOR_MIN_LENGTH));

  if (__pSD == NULL) { goto Cleanup; }
  if (!InitializeSecurityDescriptor(__pSD, SECURITY_DESCRIPTOR_REVISION)) {
    goto Cleanup;
  }

  if (!SetSecurityDescriptorDacl(__pSD, TRUE, __pACL, FALSE)) {
    goto Cleanup;
  }

  __sa.nLength = sizeof(SECURITY_ATTRIBUTES);
  __sa.lpSecurityDescriptor = __pSD;
  __sa.bInheritHandle = FALSE;

  for (const auto& __el : _mp) {
    ++i;
    _events[i] = CreateEvent(&__sa, TRUE, TRUE, NULL);
    if (_events[i] == NULL) {
      std::tout << TEXT("CreateEvent failed with: ") << GetLastError()
        << std::endl;
      goto Cleanup;
    }

    _pipes[i]._overlap.hEvent = _events[i];
    _pipes[i]._overlap.Offset = 0;
    _pipes[i]._overlap.OffsetHigh = 0;
    _pipes[i]._pid = __el.first;

    std::tstring __pipeName(PIPE_NAME);
    __pipeName += std::to_tstring(__el.first);

    _pipes[i]._pipe = CreateNamedPipe(
      __pipeName.data(),
      PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      PIPE_BUFFER_SIZE * sizeof(TCHAR),
      PIPE_BUFFER_SIZE * sizeof(TCHAR),
      PIPE_TIMEOUT,
      &__sa
    );
    if (_pipes[i]._pipe == INVALID_HANDLE_VALUE) {
      std::tout << TEXT("CreateNamedPipe failed with: ") << std::hex
        << GetLastError() << std::endl;
      goto Cleanup;
    } else {
      std::tout << TEXT("Named pipe sucessfully created for PID: ")
        << __el.first << std::endl;
    }

    _pipes[i]._pendingIO = _ConnectToNewClient(_pipes[i]._pipe,
      &_pipes[i]._overlap);

    if (!this->_InjectPid(__el.first,
      TEXT("C:\\Users\\Richelieu\\source\\repos\\Monitor\\x64\\Release\\showlibs.dll"))) {
      std::tout << TEXT("Hooking library injection failed for PID: ")
        << __el.first << std::endl;
    }
    else {
      std::tout << TEXT("Hooking library injection success for PID: ")
        << __el.first << std::endl;
    }

    _pipes[i]._state = _pipes[i]._pendingIO ? CONNECTING_STATE : OPERATING_STATE;
  }
  this->_ServerOperate();
  
Cleanup:
  if (__pEveryoneSID) { FreeSid(__pEveryoneSID); }
  if (__pAdminSID) { FreeSid(__pAdminSID); }
  if (__pACL) { LocalFree(__pACL); }
  if (__pSD) { LocalFree(__pSD); }

  return;
}

BOOL
MyProgram::
Monitor::_ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped) {
  BOOL __connected = FALSE;
  BOOL __pendingIO = FALSE;

  __connected = ConnectNamedPipe(__pipe, __lpOverlapped);
  if (__connected) {
    std::tout << TEXT("ConnectNamedPipe failed with: ") << std::hex
      << GetLastError() << std::endl;
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
        std::tout << TEXT("SetEvent failed with: ") << std::hex << __err
          << std::endl;
        return FALSE;
      }
    default: {
      __err = GetLastError();
      std::tout << TEXT("ConnectNamedPipe failed with: ") << std::hex << __err
        << std::endl;
      return FALSE;
    }
  }
  return __pendingIO;
}

void
MyProgram::
Monitor::_Disconnect(DWORD __idx) {
 if (!DisconnectNamedPipe(_pipes[__idx]._pipe)) {
    std::tout << TEXT("DisconnectNamedPipe failed with: ") << GetLastError()
      << std::endl;
  } else {
    std::tout << TEXT("Disconnected") << std::endl;
  }
}

void
MyProgram::Monitor::_ServerOperate() {

  DWORD __wait = 0;
  DWORD __cbRet = 0;
  DWORD __err = ERROR_SUCCESS;
  BOOL __success = TRUE;

  while (true) {
    __wait = WaitForMultipleObjects(
      _events.size(),
      _events.data(),
      FALSE,
      INFINITE
    );

    DWORD __idx = __wait - WAIT_OBJECT_0;
    if (__idx < 0 || size_t(__idx) + 1 > _events.size()) {
      std::tout << TEXT("Index out of range: ") << __idx << std::endl;
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
            std::tout << TEXT("Error: ") << GetLastError() << std::endl;
            return;
          }

          __success = this->_SendInit(__idx);
          if (!__success) { this->_Disconnect(__idx); }

          _pipes[__idx]._state = OPERATING_STATE;
          break;

        case OPERATING_STATE:
          if (!__success || __cbRet == 0) {
            this->_Disconnect(__idx);
            continue;
          }
          _pipes[__idx]._cbRead = __cbRet;
          break;
        default: {
          std::tout << TEXT("Invalid pipe state") << std::endl;
          return; 
        }
      }
    }
    switch (_pipes[__idx]._state) {
      case OPERATING_STATE:

        __success = ReadFile(
          _pipes[__idx]._pipe,
          _pipes[__idx]._reqBuff,
          PIPE_BUFFER_SIZE * sizeof(TCHAR),
          &_pipes[__idx]._cbRead,
          &_pipes[__idx]._overlap
        );

        if (__success && _pipes[__idx]._cbRead != 0) {
          _pipes[__idx]._pendingIO = FALSE;
          std::tout << _pipes[__idx]._reqBuff << std::endl;
          continue;
        }
        __err = GetLastError();
        if (!__success && __err == ERROR_IO_PENDING) {
          _pipes[__idx]._pendingIO = TRUE;
          continue;
        }
        this->_Disconnect(__idx);
        break;
      default: {
        std::tout << TEXT("Invalid pipe mode") << std::endl;
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
  const std::vector<std::tstring>& __funcNames =
    _mp[_pipes[__idx]._pid]._funcNames;

  __size = __funcNames.size();
  std::tout << TEXT("Sending: ") << __size << std::endl;
  __success = WriteFile(
    _pipes[__idx]._pipe,
    &__size,
    sizeof(DWORD),
    &__cbWritten,
    NULL
  );

  std::tout << TEXT("Sent: ") << __size << std::endl;
  if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }
  
  for (const auto& __str : __funcNames) {
    DWORD __strLen = __str.length();
    std::tout << TEXT("Sending: ") << __strLen << std::endl;
    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__strLen,
      sizeof(DWORD),
      &__cbWritten,
      NULL
    );
    std::tout << TEXT("Sent: ") << __strLen << std::endl;
    if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }

    std::tout << TEXT("Sending: ") << __str.data() << std::endl;
    __success = WriteFile(
      _pipes[__idx]._pipe,
      __str.data(),
      __strLen * sizeof(TCHAR),
      &__cbWritten,
      NULL
    );
    std::tout << TEXT("Sent: ") << __str.data() << std::endl;
    if (!__success && __cbWritten != __strLen * sizeof(TCHAR)) {
      return __success;
    }
  }

  // Hide names
  const std::vector<std::tstring>& __hideFilenames =
    _mp[_pipes[__idx]._pid]._hideFilenames;

  __size = __hideFilenames.size();
  std::tout << TEXT("Sending: ") << __size << std::endl;
  __success = WriteFile(
    _pipes[__idx]._pipe,
    &__size,
    sizeof(DWORD),
    &__cbWritten,
    NULL
  );

  std::tout << TEXT("Sent: ") << __size << std::endl;
  if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }
  
  for (const auto& __str : __hideFilenames) {
    DWORD __strLen = __str.length();
    std::tout << TEXT("Sending: ") << __strLen << std::endl;
    __success = WriteFile(
      _pipes[__idx]._pipe,
      &__strLen,
      sizeof(DWORD),
      &__cbWritten,
      NULL
    );
    std::tout << TEXT("Sent: ") << __strLen << std::endl;
    if (!__success && __cbWritten != sizeof(DWORD)) { return __success; }

    std::tout << TEXT("Sending: ") << __str.data() << std::endl;
    __success = WriteFile(
      _pipes[__idx]._pipe,
      __str.data(),
      __strLen * sizeof(TCHAR),
      &__cbWritten,
      NULL
    );
    std::tout << TEXT("Sent: ") << __str.data() << std::endl;
    if (!__success && __cbWritten != __strLen * sizeof(TCHAR)) {
      return __success;
    }
  }

  return __success;
}