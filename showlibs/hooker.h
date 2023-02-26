#ifndef _HOOKER_H
#define _HOOKER_H

#include "framework.h"
#include "hook_functions.h"
#include <easyhook.h>

extern "C" {

BOOL _Init();
BOOL _Run();
void _Deinit();

 void _DisconnectPipe();
 BOOL _AddHook(const std::string& __funcName);
 BOOL _ParseInit();

 BOOL _ConnectPipe();
 BOOL _RecvInit();
 
void _SendInfo(LPCSTR __funcName);

}

#endif // _HOOKER_H