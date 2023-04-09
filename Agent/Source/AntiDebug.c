//
// Created by 0xtriboulet on 4/9/2023.
//

#include "AntiDebug.h"

// Reference: https://anti-debug.checkpoint.com/

BOOL IsDebugged()
{
    // CheckRemoteDebugger MUST set this to false
    BOOL outBool = TRUE;
    CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool);

    return (IsDebuggerPresent() || outBool);

}

