#ifndef _TYPES_H
#define _TYPES_H

#include <winbase.h>
#include <iostream>

#ifdef _UNICODE
#define tout wcout
#define tstring wstring
#else 
#define tout wcout
#define tstring string
#endif

#endif // _TYPES_H
