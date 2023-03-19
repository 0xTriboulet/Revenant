//
// Created by 0xtriboulet on 3/18/2023.
//

#ifndef REVENANT_COMMANDSTRINGS_H
#define REVENANT_COMMANDSTRINGS_H


#if CONFIG_OBF_STRINGS

// PADDED STRINGS: LONGEST 26 CHARS ; find a method of padding strings automatically
#define COMMAND_DISPATCHER()     XXX("Command Dispatcher...\n\0\0\0\0\0" );
#define INSTANCE_NOT_CONNECTED() XXX("Instance not connected...\n" );
#define COMMAND_NOT_FOUND()      XXX( "Command not found !!\n\0\0\0\0\0" );
#define IS_COMMAND_NO_JOB()      XXX( "Is COMMAND_NO_JOB\n\0\0\0\0\0\0\0\0" );
#define TRANSPORT_FAILED()       XXX( "Transport: Failed\n\0\0\0\0\0\0\0\0" );

#define C_COMMAND_SHELL()        XXX( "Command::Shell\n\0\0\0\0\0\0\0\0\0\0\0" );
#define C_COMMAND_UPLOAD()       XXX( "Command::Upload\n\0\0\0\0\0\0\0\0\0\0" );
#define C_COMMAND_DOWNLOAD()     XXX( "Command::Download\n\0\0\0\0\0\0\0\0" );
#define C_COMMAND_EXIT()         XXX( "Command::Exit\n\0\0\0\0\0\0\0\0\0\0\0" );

#else

#define COMMAND_DISPATCHER()     _tprintf("%s\n","Command Dispatcher...");
#define INSTANCE_NOT_CONNECTED() _tprintf("Instance not connected...\n");
#define COMMAND_NOT_FOUND()      _tprintf( "Command not found !!\n" );
#define IS_COMMAND_NO_JOB()      _tprintf( "Is COMMAND_NO_JOB\n" );
#define TRANSPORT_FAILED()       _tprintf( "Transport: Failed\n" );

#define C_COMMAND_SHELL()        _tprintf( "Command::Shell\n" );
#define C_COMMAND_UPLOAD()       _tprintf( "Command::Upload\n" );
#define C_COMMAND_DOWNLOAD()     _tprintf( "Command::Download\n");
#define C_COMMAND_EXIT()         _tprintf( "Command::Exit" );

#endif

#endif //REVENANT_COMMANDSTRINGS_H