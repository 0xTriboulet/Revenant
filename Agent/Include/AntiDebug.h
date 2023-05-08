//
// Created by 0xtriboulet on 4/9/2023.
//

#ifndef REVENANT_ANTIDEBUG_H
#define REVENANT_ANTIDEBUG_H

#include <windows.h>
#include <debugapi.h>
#include "Structs.h"

// the constructor attribute executes this function prior to main()
BOOL __attribute__((constructor)) IsDebugged();


#endif //REVENANT_ANTIDEBUG_H
