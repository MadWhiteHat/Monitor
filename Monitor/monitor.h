#ifndef _MONITOR_H
#define _MONITOR_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>
#include <initializer_list>

#include <windows.h>

#include "../include/shared.h"

namespace MyProgram {

class Monitor {
 public:
  Monitor(const std::vector<std::string>& __args);
  void Run();

  void Print();
private:

  BOOL _InjectPid(DWORD __pid, const std::wstring& __injLib);

  DWORD _AddPid(const std::string& __pidStr);
  DWORD _GetProcIdByName(const std::string& __pidStr);
  void _AddFunc(DWORD __pid, const std::string& __funcName);
  void _AddImplFuncs(DWORD __pid);
  void _AddFilename(DWORD __pid, const std::string& __filename);

  void _CreateThreadedPipes();
  BOOL _ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped);
  void _Disconnect(DWORD __idx);
  void _ServerOperate();
  BOOL _SendInit(DWORD __idx);

  // pid, what to track
  std::unordered_map<DWORD, TRACKING> _mp;
  std::vector<PIPEINST> _pipes;
  std::vector<HANDLE> _events;
  BOOL _isGood = FALSE;
};

const std::initializer_list<std::string> _hideFuncNames = {
  "FindFirstFileA",
  "FindFirstFileW",
  "FindNextFileA",
  "FindNextFileW",
  "CreateFileA",
  "CreateFileW"
};

} // namespace MyProgram

#endif // _MONITOR_H