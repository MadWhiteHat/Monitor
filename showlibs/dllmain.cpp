// dllmain.cpp : Defines the entry point for the DLL application.

#include "pch.h"
#include "../include/shared.h"
#include "../include/types.h"

bool _CreatePipe(HANDLE* __pipe) {

  *__pipe = CreateFile(
    PIPE_NAME,
    FILE_GENERIC_READ | FILE_GENERIC_WRITE,
    FILE_SHARE_READ | FILE_SHARE_WRITE,
    NULL,
    OPEN_EXISTING,
    FILE_ATTRIBUTE_NORMAL,
    NULL
  );

  if (*__pipe == INVALID_HANDLE_VALUE) { return false; }
  if (GetLastError() != ERROR_PIPE_BUSY) {
    *__pipe = INVALID_HANDLE_VALUE;
    return false;
  }
  if (!WaitNamedPipe(PIPE_NAME, 20000)) {
    *__pipe = INVALID_HANDLE_VALUE;
    false;
  }
  return false;
}

BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     ) {
  HANDLE __pipe = INVALID_HANDLE_VALUE;

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {

    TCHAR __buff[PIPE_BUFFER_SIZE] = { 0x00 };
    DWORD __totalWritten = 0;
    bool __isOk = false;

    __isOk = _CreatePipe(&__pipe);

    while (__isOk) {
      ZeroMemory(__buff, PIPE_BUFFER_SIZE * sizeof(TCHAR));

      StringCbCopy(__buff, PIPE_BUFFER_SIZE * sizeof(TCHAR),
        TEXT("Hi, there!"));

      __isOk = WriteFile(
        __pipe,
        __buff,
        PIPE_BUFFER_SIZE * sizeof(TCHAR),
        &__totalWritten,
        NULL
      );

      Sleep(1000);
    }
  } else if (ul_reason_for_call == DLL_PROCESS_DETACH) {
    if (__pipe != INVALID_HANDLE_VALUE) {
      CloseHandle(__pipe);
    }
  }
    return TRUE;
}

