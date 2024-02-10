#include "singleton.h"

Singleton* Singleton::_instance = nullptr;

Singleton* Singleton::Instance() {
  if (_instance == nullptr) {
    _instance = new Singleton();
  }

  return _instance;
}
