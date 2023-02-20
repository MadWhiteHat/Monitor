// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "../include/shared.h"
#include "../include/types.h"

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
  HANDLE __pipe = INVALID_HANDLE_VALUE;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    TCHAR __buff[PIPE_BUFFER_SIZE] = { 0x00 };
    BOOL __success = FALSE;
    DWORD __cbRead = 0;
    DWORD __cbToWrite = 0;
    DWORD __cbWritten = 0;
    DWORD __mode = 0;

    while (true) {
      __pipe = CreateFile(
        PIPE_NAME,
        GENERIC_READ | GENERIC_WRITE,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL
      );

      if (__pipe != INVALID_HANDLE_VALUE) { break; }

      if (GetLastError() != ERROR_PIPE_BUSY) { return FALSE; }
      if (!WaitNamedPipe(PIPE_NAME, 20000)) { return FALSE; }
    }

    __mode = PIPE_READMODE_MESSAGE;
    __success = SetNamedPipeHandleState(__pipe, &__mode, NULL, NULL);
    if (!__success) {
      CloseHandle(__pipe);
      return FALSE;
    }

    auto __msg1 = TEXT("Default message from client");
    __cbToWrite = (lstrlen(__msg1) + 1) * sizeof(TCHAR);
   
    __success = WriteFile(
      __pipe,
      __msg1,
      __cbToWrite,
      &__cbWritten,
      NULL
    );

    auto __msg2 = TEXT("Default message from client2");
    __cbToWrite = (lstrlen(__msg2) + 1) * sizeof(TCHAR);
   
    __success = WriteFile(
      __pipe,
      __msg2,
      __cbToWrite,
      &__cbWritten,
      NULL
    );

  } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    if (__pipe != INVALID_HANDLE_VALUE) {
      CloseHandle(__pipe);
    }
  }
    return TRUE;
}

