//
// Created by 0xtriboulet on 4/9/2023.
//

#include "Config.h"
#include "AntiDebug.h"
// Provides basic anti-debugging and anti-emulation techniques. Easily bypassable by analysis
// References:
//   Checkpoint:        https://anti-debug.checkpoint.com/
//   0xPat's blog here: https://0xpat.github.io/Malware_development_part_2/

BOOL IsDebugged()
{
#if CONFIG_ANTI_DEBUG
    // CheckRemoteDebugger MUST set this to false
    BOOL outBool = TRUE;
    CheckRemoteDebuggerPresent(NtCurrentProcess, &outBool);
    if (IsDebuggerPresent() || outBool) return TRUE;

    // check CPU
    SYSTEM_INFO systemInfo;
    GetSystemInfo(&systemInfo);
    DWORD numberOfProcessors = systemInfo.dwNumberOfProcessors;
    if (numberOfProcessors < 2) return TRUE;

    // check RAM
    MEMORYSTATUSEX memoryStatus;
    memoryStatus.dwLength = sizeof(memoryStatus);
    GlobalMemoryStatusEx(&memoryStatus);
    DWORD RAMMB = memoryStatus.ullTotalPhys / 1024 / 1024;
    if (RAMMB < 2048) return TRUE;

    // check HDD
    HANDLE hDevice = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);
    DISK_GEOMETRY pDiskGeometry;
    DWORD bytesReturned;
    DeviceIoControl(hDevice, IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &pDiskGeometry, sizeof(pDiskGeometry), &bytesReturned, (LPOVERLAPPED)NULL);
    DWORD diskSizeGB;
    diskSizeGB = pDiskGeometry.Cylinders.QuadPart * (ULONG)pDiskGeometry.TracksPerCylinder * (ULONG)pDiskGeometry.SectorsPerTrack * (ULONG)pDiskGeometry.BytesPerSector / 1024 / 1024 / 1024;
    if (diskSizeGB < 100) TRUE;


#endif // CONFIG_ANTI_DEBUG

    return FALSE;
}

