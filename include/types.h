#ifndef _TYPES_H
#define _TYPES_H

#include <winbase.h>
#include <iostream>
#include <string>

#ifdef _UNICODE
#define tout wcout
#define tstring wstring
#define to_tstring to_wstring
#else 
#define tout cout
#define tstring string
#define to_tstring to_string
#endif

#endif // _TYPES_H
