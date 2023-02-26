// dllmain.cpp : Defines the entry point for the DLL application.

#include "framework.h"
#include "hooker.h"

extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO*);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* __inRemoteInfo) {
  DWORD __mode = *(reinterpret_cast<DWORD*>(__inRemoteInfo->UserData));
  switch (__mode) {
    case INJECT_DLL:
      if (!_Init()) { return; }
      if (!_Run()) { return; }
      break;
    case EJECT_DLL:
      _Deinit();
      break;
    default:
      break;
  }
}
