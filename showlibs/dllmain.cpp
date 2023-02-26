// dllmain.cpp : Defines the entry point for the DLL application.

#include "framework.h"
#include "hooker.h"

DWORD WINAPI CommunicationThread(LPVOID) {

  if (!_Init()) { return -1; }
  if (!_Run()) { return -1; }
  
  return 0;
}

HANDLE __thread = NULL;


extern "C" void __declspec(dllexport) __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO*);

void __stdcall NativeInjectionEntryPoint(REMOTE_ENTRY_INFO* __inRemoteInfo) {
  DWORD __threadId = 0;
  __thread = CreateThread(
    NULL,
    0,
    CommunicationThread,
    NULL,
    0,
    &__threadId
  );
}
