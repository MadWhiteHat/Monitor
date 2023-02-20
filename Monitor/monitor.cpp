#include <string>
#include <windows.h>
#include <tlhelp32.h>
#include <aclapi.h>

#include "../include/shared.h"
#include "../include/types.h"
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
  bool __connected = false;
  DWORD __threadId = -1;
  HANDLE __pipe = INVALID_HANDLE_VALUE;
  HANDLE __thread = NULL;
  std::vector<HANDLE> __vt;

  PSID __pEveryoneSID = NULL;
  PSID __pAdminSID = NULL;
  PACL __pACL = NULL;
  PSECURITY_DESCRIPTOR __pSD = NULL;
  EXPLICIT_ACCESS __ea[2];
  SID_IDENTIFIER_AUTHORITY __SIDAuthAll = SECURITY_WORLD_SID_AUTHORITY;
  SID_IDENTIFIER_AUTHORITY __SIDAuthNT = SECURITY_NT_AUTHORITY;
  SECURITY_ATTRIBUTES __sa;

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

    __pipe = CreateNamedPipe(
      PIPE_NAME,
      PIPE_ACCESS_DUPLEX,
      PIPE_TYPE_MESSAGE | PIPE_READMODE_MESSAGE | PIPE_WAIT,
      PIPE_UNLIMITED_INSTANCES,
      PIPE_BUFFER_SIZE * sizeof(TCHAR),
      PIPE_BUFFER_SIZE * sizeof(TCHAR),
      NMPWAIT_USE_DEFAULT_WAIT,
      &__sa
    );
    if (__pipe == INVALID_HANDLE_VALUE) {
      std::tout << TEXT("CreateNamedPipe failed with: ") << std::hex
        << GetLastError() << std::endl;
      goto Cleanup;
    } else {
      std::tout << TEXT("Named pipe sucessfully created for PID") << __el.first
        << std::endl;
    }

    if (!this->_InjectPid(__el.first,
      TEXT("C:\\Users\\Richelieu\\source\\repos\\Monitor\\x64\\Release\\showlibs.dll"))) {
      std::tout << TEXT("Hooking library injection failed") << std::endl;
    }
    else {
      std::tout << TEXT("Hooking library injection success");
    }

    __connected = ConnectNamedPipe(__pipe, NULL) ? true
      : (GetLastError() == ERROR_PIPE_CONNECTED);

    if (__connected) {
      std::tout << TEXT("Pipe connection success") << std::endl;
      __thread = CreateThread(
        NULL,
        0,
        InstanceThread,
        reinterpret_cast<LPVOID>(__pipe),
        0,
        &__threadId
      );
      if (__thread == NULL) {
        std::tout << TEXT("CreateThread failed with: ") << std::hex
          << GetLastError() << std::endl;
      } else {
        __vt.push_back(__thread);
      }
    } else {
      std::tout << TEXT("Pipe connection failed with: ") << std::hex <<
        GetLastError() << std::endl;
      CloseHandle(__pipe); }
  }
  if (__vt.size()) {
    WaitForMultipleObjects(
      __vt.size(),
      __vt.data(),
      true,
      INFINITE
    );
  }
  for (const auto __thread : __vt) { CloseHandle(__thread); }

Cleanup:
  if (__pEveryoneSID) { FreeSid(__pEveryoneSID); }
  if (__pAdminSID) { FreeSid(__pAdminSID); }
  if (__pACL) { LocalFree(__pACL); }
  if (__pSD) { LocalFree(__pSD); }

  return;
}

DWORD WINAPI
MyProgram::
InstanceThread(LPVOID __param) {
  HANDLE __heap = GetProcessHeap();
  if (__heap == NULL) { return -1; }
  TCHAR* __message = static_cast<TCHAR*>(HeapAlloc(__heap, 0, PIPE_BUFFER_SIZE
    * sizeof(TCHAR)));
  DWORD __totalBytesRead = 0;
  bool __isOk = false;
  if (__param == NULL) {
    if (__message != NULL) { HeapFree(__heap, 0, __message); }
    return -1;
  }
  if (__message == NULL) { return -1; }
  HANDLE __pipe = reinterpret_cast<HANDLE>(__param);

  // Processing
  while (true) {
    std::cout << "Read file" << std::endl;
    __isOk = ReadFile(
      __pipe,
      __message,
      PIPE_BUFFER_SIZE * sizeof(TCHAR),
      &__totalBytesRead,
      NULL
    );
    std::cout << "Passed" << std::endl;
    if (!__isOk || __totalBytesRead == 0) {
      if (GetLastError() == ERROR_BROKEN_PIPE) {
        std::tout << TEXT("Client disconected");
      } else { std::tout << TEXT("Read data from pipe failed"); }
      break;
    }
    else { std::tout << __message << std::endl; }
  }
  FlushFileBuffers(__pipe);
  DisconnectNamedPipe(__pipe);
  CloseHandle(__pipe);
  
  HeapFree(__heap, 0, __message);
  return 0;
}