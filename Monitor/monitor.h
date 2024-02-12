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
  // Parser part
  std::vector<DWORD> _AddProc(const std::string& __procStr);
  std::vector<DWORD> _GetProcIdsByName(const std::string& __pidStr);
  void _AddImplFuncs(DWORD __pid);
  void _AddFunc(
    const std::vector<DWORD>& __pids,
    const std::string& __funcName
  );
  void _AddFilename(
    const std::vector<DWORD>& __pids,
    const std::string& __filename
  );

  // Injection part
  BOOL _CreatePipes();
  void _ConnectToAllClients();
  BOOL _ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped);
  BOOL _InjectLibAll();
  BOOL _InjectLibByPid(DWORD __pid, const std::wstring& __injLib);
  void _Disconnect(DWORD __idx);
  BOOL _AllDisconnected();
  void _ServerOperate();
  BOOL _SendInit(DWORD __idx);

  // pid, what to track
  std::unordered_map<DWORD, TRACKING> _pidToTrackingInfo;
  std::unordered_map<DWORD, std::string> _pidToProcName;
  std::vector<PIPEINST> _pipes;
  std::vector<HANDLE> _events;
};

static std::initializer_list<std::string> _hideFuncNames = {
  "FindFirstFileA",
  "FindFirstFileW",
  "FindNextFileA",
  "FindNextFileW",
  "CreateFileA",
  "CreateFileW"
};

} // namespace MyProgram

#endif // _MONITOR_H