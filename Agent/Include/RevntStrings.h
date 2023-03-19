//
// Created by 0xtriboulet on 3/18/2023.
//

#ifndef REVENANT_COMMANDSTRINGS_H
#define REVENANT_COMMANDSTRINGS_H
#include <stdlib.h>
#include <Config.h>
#include <ObfuscateStrings.h>

extern void * MemCopy(void* dest, const void* src, size_t n);

#if CONFIG_OBF_STRINGS

#define CACHE char CACHE_STR[100]

// XXX() is the macro that obfuscates and prints the strings
// PADDED STRINGS: LONGEST 26 CHARS ; find a method of padding strings automatically
#define sNtdll         XXX("ntdll.dll\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0")

#define sRtlRandomEx(str)   MemCopy(str, XXX("RtlRandomEx\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0"), 12)
#define sRtlGetVersion(str) MemCopy(str, XXX("RtlGetVersion\0\0\0\0\0\0\0\0\0\0\0\0\0\0"), 14)


#define COMMAND_DISPATCHER()     _tprintf( XXX( "Command Dispatcher...\n\0\0\0\0\0" ));
#define INSTANCE_NOT_CONNECTED() _tprintf( XXX( "Instance not connected...\n" ));
#define COMMAND_NOT_FOUND()      _tprintf( XXX( "Command not found !!\n\0\0\0\0\0" ));
#define IS_COMMAND_NO_JOB()      _tprintf( XXX( "Is COMMAND_NO_JOB\n\0\0\0\0\0\0\0\0" ));
#define TRANSPORT_FAILED()       _tprintf( XXX( "Transport: Failed\n\0\0\0\0\0\0\0\0" ));

#define C_COMMAND_SHELL()        _tprintf( XXX( "Command::Shell\n\0\0\0\0\0\0\0\0\0\0\0" ));
#define C_COMMAND_UPLOAD()       _tprintf( XXX( "Command::Upload\n\0\0\0\0\0\0\0\0\0\0" ));
#define C_COMMAND_DOWNLOAD()     _tprintf( XXX( "Command::Download\n\0\0\0\0\0\0\0\0" ));
#define C_COMMAND_EXIT()         _tprintf( XXX( "Command::Exit\n\0\0\0\0\0\0\0\0\0\0\0" ));

#else
#define sNtdll              "ntdll.dll"

#define sRtlRandomEx(str)   "RtlRandomEx"
#define sRtlGetVersion(str) "RtlGetVersion"

#define COMMAND_DISPATCHER()     _tprintf( "Command Dispatcher...\n");
#define INSTANCE_NOT_CONNECTED() _tprintf( "Instance not connected...\n");
#define COMMAND_NOT_FOUND()      _tprintf( "Command not found !!\n" );
#define IS_COMMAND_NO_JOB()      _tprintf( "Is COMMAND_NO_JOB\n" );
#define TRANSPORT_FAILED()       _tprintf( "Transport: Failed\n" );

#define C_COMMAND_SHELL()        _tprintf( "Command::Shell\n" );
#define C_COMMAND_UPLOAD()       _tprintf( "Command::Upload\n" );
#define C_COMMAND_DOWNLOAD()     _tprintf( "Command::Download\n");
#define C_COMMAND_EXIT()         _tprintf( "Command::Exit" );

#endif


#endif //REVENANT_COMMANDSTRINGS_H