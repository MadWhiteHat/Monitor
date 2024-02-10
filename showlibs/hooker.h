#ifndef _HOOKER_H
#define _HOOKER_H

#include "framework.h"

extern TRACKING _track;
extern std::unordered_map<std::string, FARPROC> _funcMap;

BOOL _Init();
BOOL _Run();
void _Deinit();

void _DisconnectPipe();
BOOL _AddHook(const std::string& __funcName);
BOOL _ParseInit();

BOOL _ConnectPipe();
BOOL _RecvInit();
 
void _SendInfo(std::string funcName);

#endif // _HOOKER_H