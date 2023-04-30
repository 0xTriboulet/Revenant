//
// Created by 0xtriboulet on 4/21/2023.
//

#ifndef REVENANT_ASM_H
#define REVENANT_ASM_H
#include <windows.h>
#include "Config.h"

#if CONFIG_ARCH == 64
PVOID get_ntdll_64();

#else
PVOID get_ntdll_32();

#endif


#endif //REVENANT_ASM_H
