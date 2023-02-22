#include "framework.h"
#include "hooker.h"

MyProgram::
Hooker::Hooker() {
  _pipeInst._pipe = INVALID_HANDLE_VALUE;
  _pipeInst._pid = GetCurrentProcessId();
}

MyProgram::
Hooker::~Hooker() { this->_DisconnectPipe(); }

BOOL
MyProgram::
Hooker::Run() {
  if (!this->_ConnectPipe()) { return FALSE; }
  if (!this->_RecvInit()) { return FALSE; }

  return TRUE;
}

BOOL
MyProgram::
Hooker::_ConnectPipe() {
  BOOL __success = FALSE;
  DWORD __mode = 0;

  std::tstring __pipeName(PIPE_NAME);
  __pipeName += std::to_tstring(_pipeInst._pid);

  while (true) {
    _pipeInst._pipe = CreateFile(
      __pipeName.data(),
      GENERIC_READ | GENERIC_WRITE,
      0,
      NULL,
      OPEN_EXISTING,
      FILE_ATTRIBUTE_NORMAL,
      NULL
    );

    if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { break; }

    if (GetLastError() != ERROR_PIPE_BUSY) { return FALSE; }
    if (!WaitNamedPipe(PIPE_NAME, 20000)) { return FALSE; }
  }

  __mode = PIPE_READMODE_MESSAGE;
  __success = SetNamedPipeHandleState(_pipeInst._pipe, &__mode, NULL, NULL);

  return __success;
}

BOOL
MyProgram::
Hooker::_RecvInit() {
  
  BOOL __success = FALSE;
  DWORD __size = 0;

  __success = ReadFile(
    _pipeInst._pipe,
    &__size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!__success) { return FALSE; }

  for (DWORD __idx = 0; __idx < __size; ++__idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    DWORD __strLen = 0;
    __success = ReadFile(
      _pipeInst._pipe,
      &__strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success || __strLen == 0) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      __strLen * sizeof(TCHAR),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }

    _track._funcNames.emplace_back(_pipeInst._reqBuff, __strLen);
  }

  // Hide filenames
  __success = ReadFile(
    _pipeInst._pipe,
    &__size,
    sizeof(DWORD),
    &_pipeInst._cbRead,
    NULL
  );

  if (!__success) { return FALSE; }

  for (DWORD __idx = 0; __idx < __size; ++__idx) {
    ZeroMemory(_pipeInst._reqBuff, PIPE_BUFFER_SIZE * sizeof(TCHAR));
    DWORD __strLen = 0;
    __success = ReadFile(
      _pipeInst._pipe,
      &__strLen,
      sizeof(DWORD),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success || __strLen == 0) { return FALSE; }

    __success = ReadFile(
      _pipeInst._pipe,
      _pipeInst._reqBuff,
      __strLen * sizeof(TCHAR),
      &_pipeInst._cbRead,
      NULL
    );

    if (!__success) { return FALSE; }

    _track._hideFilenames.emplace_back(_pipeInst._reqBuff, __strLen);
  }

  return TRUE;
}

void
MyProgram::
Hooker::_DisconnectPipe() {
  if (_pipeInst._pipe != INVALID_HANDLE_VALUE) { CloseHandle(_pipeInst._pipe); }
}
