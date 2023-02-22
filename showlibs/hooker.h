#ifndef _HOOKER_H
#define _HOOKER_H

#include "framework.h"

namespace MyProgram {

class Hooker {
 public:
  Hooker();
  BOOL Run();
  ~Hooker();

 private:
   void _DisconnectPipe();

   BOOL _ConnectPipe();
   BOOL _RecvInit();

   PIPEINST _pipeInst;
   Tracking _track;
};

} // namespace MyProgram

#endif // _HOOKER_H