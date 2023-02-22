#ifndef _SHARED_H
#define _SHARED_H

#include "types.h"
#include <vector>

#define PIPE_NAME TEXT("\\\\.\\pipe\\monitor")
#define PIPE_BUFFER_SIZE 2048
#define PIPE_TIMEOUT 5000
#define CONNECTING_STATE 0
#define OPERATING_STATE 1

typedef struct {
  OVERLAPPED _overlap;
  HANDLE _pipe;
  TCHAR _reqBuff[PIPE_BUFFER_SIZE];
  DWORD _cbRead;
  TCHAR _replyBuff[PIPE_BUFFER_SIZE];
  DWORD _cbToWrite;
  DWORD _state;
  DWORD _pid;
  BOOL _pendingIO;
} PIPEINST, *LPPIPEINST;

struct Tracking {
  std::vector<std::tstring> _funcNames;
  std::vector<std::tstring> _hideFilenames;
};

#endif _SHARED_H