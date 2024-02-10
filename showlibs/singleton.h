#ifndef _SINGLETON
#define _SINGLETON

#include "framework.h"
#include <unordered_map>
#include <vector>

class Singleton {
public:

  static Singleton* Instance();

private:
  static Singleton* _instance;

  Singleton() {}
  ~Singleton() {}
  Singleton(const Singleton&) = delete;
  Singleton(Singleton&&) = delete;
  Singleton& operator=(const Singleton&) = delete;
  Singleton& operator=(Singleton&&) = delete;
};

#endif // !_SINGLETON
