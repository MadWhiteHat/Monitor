#ifndef _MONITOR_H
#define _MONITOR_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/shared.h"

namespace MyProgram {

extern "C" {
  DWORD WINAPI InstanceThread(LPVOID __pipe);
}

class Monitor {
 public:
  Monitor(const std::vector<std::tstring>& __args);
  void Run();
  
  void Print() {
    for (const auto& __el : _mp) {
      std::tout << TEXT("Pid: ") << __el.first << std::endl;
      std::tout << TEXT("\tFunctions:") << std::endl;
      for (const auto& __name : __el.second._funcNames) {
        std::tout << TEXT("\t\t") << __name << std::endl;
      }
      std::tout << TEXT("\tHide:") << std::endl;
      for (const auto& __name : __el.second._hideFilenames) {
        std::tout << TEXT("\t\t") << __name << std::endl;
      }
    }
  }


private:

  bool _InjectAll(const std::tstring& __injLib);
  bool _InjectPid(DWORD __pid, const std::tstring& __injLib);

  DWORD _AddPid(const std::tstring& __pidStr);
  DWORD _GetProcIdByName(const std::tstring& __pidStr);
  void _AddFunc(DWORD __pid, const std::tstring& __funcName);
  void _AddFilename(DWORD __pid, const std::tstring& __filename);

  void _CreateThreadedPipes();
  BOOL _ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped);
  void _Disconnect(DWORD __idx);
  void _ServerOperate();
  BOOL _SendInit(DWORD __idx);

  // pid, what to track
  std::unordered_map<DWORD, Tracking> _mp;
  std::vector<PIPEINST> _pipes;
  std::vector<HANDLE> _events;
  bool _isGood = false;
};

} // namespace MyProgram

#endif // _MONITOR_H