//
// Created by 0xtriboulet on 3/25/2023.
//

#ifndef REVENANT_DEFS_H
#define REVENANT_DEFS_H

#include "Structs.h"
#include <windows.h>

#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }

typedef BOOLEAN  (__stdcall *RtlFreeHeap_t)(PVOID HeapHandle,ULONG Flags,PVOID BaseAddress);
typedef VOID     (__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);
typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
typedef PVOID    (__stdcall *RtlAllocateHeap_t)(PVOID HeapHandle,ULONG Flags,SIZE_T Size);
typedef ULONG    (__stdcall *RtlGetProcessHeaps_t)(ULONG NumberOfHeaps,PVOID* ProcessHeaps);
typedef NTSTATUS (__stdcall *NtClose_t)(HANDLE);
typedef BOOLEAN  (__stdcall *RtlDosPathNameToNtPathName_U_t)(PCWSTR DosFileName,PUNICODE_STRING NtFileName,PWSTR* FilePart,PVOID Reserved);
typedef NTSTATUS (__stdcall *RtlMultiByteToUnicodeN_t)(PWCH UnicodeString,ULONG MaxBytesInUnicodeString,PULONG BytesInUnicodeString,PCSTR MultiByteString,ULONG BytesInMultiByteString);
typedef NTSTATUS (__stdcall *NtReadFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS (__stdcall *LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);
typedef NTSTATUS (__stdcall *NtOpenFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,ULONG OpenOptions);
typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
typedef NTSTATUS (__stdcall *NtWriteFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (__stdcall *NtCreateUserProcess_t)(PHANDLE ProcessHandle,PHANDLE ThreadHandle,ACCESS_MASK ProcessDesiredAccess,ACCESS_MASK ThreadDesiredAccess,POBJECT_ATTRIBUTES ProcessObjectAttributes,POBJECT_ATTRIBUTES ThreadObjectAttributes,ULONG ProcessFlags,ULONG ThreadFlags,PRTL_USER_PROCESS_PARAMETERS ProcessParameters,PPS_CREATE_INFO CreateInfo,PPS_ATTRIBUTE_LIST AttributeList);
typedef NTSTATUS (__stdcall *RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,PUNICODE_STRING ImagePathName,PUNICODE_STRING DllPath,PUNICODE_STRING CurrentDirectory,PUNICODE_STRING CommandLine,PVOID Environment,PUNICODE_STRING WindowTitle,PUNICODE_STRING DesktopInfo,PUNICODE_STRING ShellInfo,PUNICODE_STRING RuntimeData,ULONG Flags);
typedef NTSTATUS (__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, DWORD NewProtect, PULONG OldProtect);
typedef NTSTATUS (__stdcall *NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (__stdcall *NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,PULONG NumberOfBytesWritten);
typedef NTSTATUS (__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,SIZE_T BufferSize,PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (__stdcall *NtSetInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (__stdcall *NtCreateProcess_t)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ParentProcess,BOOLEAN InheritObjectTable,HANDLE SectionHandle,HANDLE DebugPort,HANDLE ExceptionPort);
typedef NTSTATUS (__stdcall *NtCreateProcessEx_t)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ParentProcess,ULONG Flags,HANDLE SectionHandle,HANDLE DebugPort,HANDLE ExceptionPort,BOOLEAN InJob);
typedef NTSTATUS (__stdcall *RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);

#endif //REVENANT_DEFS_H

