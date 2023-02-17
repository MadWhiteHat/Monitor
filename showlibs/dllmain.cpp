// dllmain.cpp : Defines the entry point for the DLL application.
#include "pch.h"
#include <string>
#include <iostream>
#include <fstream>

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
  if (ul_reason_for_call == DLL_PROCESS_ATTACH
      || ul_reason_for_call == DLL_THREAD_ATTACH) {
    PBYTE __pb = NULL;
    MEMORY_BASIC_INFORMATION __mbi;

    while (VirtualQuery(__pb, &__mbi, sizeof(__mbi)) == sizeof(__mbi)) {
      int32_t __len = 0;
      CHAR __modName[MAX_PATH] = { 0x00 };

      if (__mbi.State == MEM_FREE) {
        __mbi.AllocationBase = __mbi.BaseAddress;
      }

      if (__mbi.AllocationBase == hModule
        || __mbi.AllocationBase != __mbi.BaseAddress
        || __mbi.AllocationBase == NULL) { __len = 0; }
      else {
        __len = GetModuleFileNameA(
          reinterpret_cast<HINSTANCE>(__mbi.AllocationBase),
          __modName, MAX_PATH);
      }

      if (__len > 0) {
        std::fstream __fd("C:\\Users\\Richelieu\\source\\repos\\Monitor\\hello.txt", std::ios_base::out || std::ios_base::ate);
        if (__fd.is_open()) {
          __fd << std::hex << __mbi.AllocationBase << "-" << __modName << std::endl;
          __fd.close();
        }
      }
    }
  }
    
    return TRUE;
}

