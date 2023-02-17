#include <string>
#include <windows.h>
#include <tlhelp32.h>

#include "types.h"
#include "monitor.h"

#define _CRT_SECURE_NNO_WARNINGS

void
MyProgram::
Monitor::Run() {
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

void
MyProgram::
Monitor::_Inject(const std::tstring& __injLib) {
  for (const auto& __el : _mp) {
    HANDLE __hProc = NULL;
    __hProc = OpenProcess(
      PROCESS_CREATE_THREAD         // CreateRemoteThread
      | PROCESS_VM_WRITE            // VirtualAllocEx/VirtualFreeEx 
      | PROCESS_VM_OPERATION,       // WriteProcessMemory
      FALSE, __el.first
    );
    if (__hProc == NULL) {
      std::tout << TEXT("Cannot open process") << std::endl;
      return;
    }
    PTSTR __libFileRemote = NULL;
    __libFileRemote = reinterpret_cast<PTSTR>(
      VirtualAllocEx(__hProc, NULL, __injLib.size(), MEM_COMMIT, PAGE_READWRITE));
    if (__libFileRemote == NULL) {
      std::tout << TEXT("Cannot allocate memory at remote process") << std::endl;
      CloseHandle(__hProc);
    }
    if (!WriteProcessMemory(__hProc, __libFileRemote,
      reinterpret_cast<LPCVOID>(__injLib.data()), __injLib.size(), NULL)) {

      std::tout << TEXT("Cannot write process memory") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
    }
    LPTHREAD_START_ROUTINE __threadRoutine =
      reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(
        GetModuleHandle(TEXT("kernel32.dll")),
#ifdef _UNICODE
        "LoadLibraryW"
#else
        "LoadLibraryA"
#endif
      ));
    if (__threadRoutine == NULL) {
      std::tout << TEXT("Cannot get LoadLibrary") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
    }
    
    HANDLE __remoteThread = NULL;
    __remoteThread = CreateRemoteThread(__hProc, NULL, 0, __threadRoutine,
      __libFileRemote, 0, NULL);
    if (__remoteThread == NULL) {
      std::tout << TEXT("Cannot create remote thread") << std::endl;
      VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
      CloseHandle(__hProc);
    }

    WaitForSingleObject(__remoteThread, INFINITE);

    VirtualFreeEx(__hProc, __libFileRemote, 0, MEM_RELEASE);
    CloseHandle(__remoteThread);
    CloseHandle(__hProc);
  }
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