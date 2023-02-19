#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include "../include/types.h"
#include "monitor.h"

int32_t main(const int32_t argc, const char** argv) {

  std::vector<std::tstring> __command;
  for (int32_t idx = 1; idx < argc; ++idx) {
#ifdef _UNICODE
    auto __len = strlen(argv[idx]);
    std::tstring __tmpStr;
    __tmpStr.assign(__len, '\0');
    std::mbstowcs(const_cast<WCHAR*>(__tmpStr.data()), argv[idx],
      __tmpStr.length());
    __command.push_back(std::move(__tmpStr));
#else
    __command.emplace_back(argv[idx]);
#endif
  }

  MyProgram::Monitor __monitor(__command);
  __monitor.Print();
  __monitor.Run();

  return 0;
}