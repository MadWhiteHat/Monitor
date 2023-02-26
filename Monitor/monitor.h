#ifndef _MONITOR_H
#define _MONITOR_H

#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

#include "../include/shared.h"

namespace MyProgram {

class Monitor {
 public:
  Monitor(const std::vector<std::string>& __args);
  void Run();
  
  void Print() {
    for (const auto& __el : _mp) {
      std::cout << "Pid: " << __el.first << std::endl;
      std::cout << "\tFunctions:" << std::endl;
      for (const auto& __name : __el.second._funcNames) {
        std::cout << "\t\t" << __name << std::endl;
      }
      std::cout << "\tHideA:" << std::endl;
      for (const auto& __name : __el.second._hideFilenamesA) {
        std::cout << "\t\t" << __name << std::endl;
      }
      std::cout << "\tHideW:" << std::endl;
      for (const auto& __name : __el.second._hideFilenamesW) {
        std::wcout << "\t\t" << __name << std::endl;
      }
    }
  }


private:

  BOOL _InjectPid(DWORD __pid, const std::wstring& __injLib);

  DWORD _AddPid(const std::string& __pidStr);
  DWORD _GetProcIdByName(const std::string& __pidStr);
  void _AddFunc(DWORD __pid, const std::string& __funcName);
  void _AddFilename(DWORD __pid, const std::string& __filename);

  void _CreateThreadedPipes();
  BOOL _ConnectToNewClient(HANDLE __pipe, LPOVERLAPPED __lpOverlapped);
  void _Disconnect(DWORD __idx);
  void _ServerOperate();
  BOOL _SendInit(DWORD __idx);

  // pid, what to track
  std::unordered_map<DWORD, Tracking> _mp;
  std::vector<PIPEINST> _pipes;
  std::vector<HANDLE> _events;
  BOOL _isGood = FALSE;
};

} // namespace MyProgram

#endif // _MONITOR_H