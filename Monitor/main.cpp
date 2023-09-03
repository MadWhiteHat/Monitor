#define _CRT_SECURE_NO_WARNINGS

#include <iostream>
#include <string>
#include <vector>
#include <cstdlib>

#include "monitor.h"

int32_t main(const int32_t argc, const char** argv) {

  std::vector<std::string> __command;
  for (int32_t idx = 1; idx < argc; ++idx) {
    __command.emplace_back(argv[idx]);
  }

  MyProgram::Monitor __monitor(__command);
  __monitor.Print();
  __monitor.Run();

  return 0;
}