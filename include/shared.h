#ifndef _SHARED_H
#define _SHARED_H

#include <iostream>
#include <vector>
#include <unordered_map>

#include <windef.h>

#define PIPE_NAME "\\\\.\\pipe\\monitor"
#define PIPE_BUFFER_SIZE 4096
#define PIPE_TIMEOUT 5000
#define CONNECTING_STATE 0
#define OPERATING_STATE 1
#define DISCONNECTED_STATE 2

#define INJECT_DLL DWORD(0)
#define EJECT_DLL DWORD(1)

typedef struct {
  OVERLAPPED _overlap;
  HANDLE _pipe;
  CHAR _reqBuff[PIPE_BUFFER_SIZE];
  DWORD _cbRead;
  CHAR _replyBuff[PIPE_BUFFER_SIZE];
  DWORD _cbToWrite;
  DWORD _state;
  DWORD _pid;
  BOOL _pendingIO;
} PIPEINST, *LPPIPEINST;

struct Tracking {
  std::unordered_map<std::string, BOOL> _funcNames;
  std::vector<std::string> _hideFilenamesA;
  std::vector<std::wstring> _hideFilenamesW;
};

#endif _SHARED_H