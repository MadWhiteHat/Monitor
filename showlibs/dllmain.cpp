// dllmain.cpp : Defines the entry point for the DLL application.

#include "framework.h"
#include "hooker.h"

DWORD WINAPI CommunicationThread(LPVOID) {

  MyProgram::Hooker __hooker;
  if (!__hooker.Run()) { return -1; }
  
  return 0;
}

HANDLE __thread = NULL;

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    DWORD __threadId = 0;
    __thread = CreateThread(
      NULL,
      0,
      CommunicationThread,
      NULL,
      0,
      &__threadId
    );
    if (__thread == NULL) { return FALSE; }
  } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    if (__thread != NULL) {
      WaitForSingleObject(__thread, INFINITE);
      CloseHandle(__thread);
    }
  }
    return TRUE;
}
