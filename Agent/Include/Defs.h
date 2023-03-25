//
// Created by 0xtriboulet on 3/25/2023.
//

#ifndef REVENANT_DEFS_H
#define REVENANT_DEFS_H

#include "Structs.h"
#include <windows.h>

typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);


#endif //REVENANT_DEFS_H

