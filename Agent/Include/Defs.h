//
// Created by 0xtriboulet on 3/25/2023.
//

#ifndef REVENANT_DEFS_H
#define REVENANT_DEFS_H

#include "Structs.h"
#include <windows.h>


// private
typedef enum _PS_ATTRIBUTE_NUM
{
    PsAttributeParentProcess, // in HANDLE
    PsAttributeDebugObject, // in HANDLE
    PsAttributeToken, // in HANDLE
    PsAttributeClientId, // out PCLIENT_ID
    PsAttributeTebAddress, // out PTEB *
    PsAttributeImageName, // in PWSTR
    PsAttributeImageInfo, // out PSECTION_IMAGE_INFORMATION
    PsAttributeMemoryReserve, // in PPS_MEMORY_RESERVE
    PsAttributePriorityClass, // in UCHAR
    PsAttributeErrorMode, // in ULONG
    PsAttributeStdHandleInfo, // 10, in PPS_STD_HANDLE_INFO
    PsAttributeHandleList, // in HANDLE[]
    PsAttributeGroupAffinity, // in PGROUP_AFFINITY
    PsAttributePreferredNode, // in PUSHORT
    PsAttributeIdealProcessor, // in PPROCESSOR_NUMBER
    PsAttributeUmsThread, // ? in PUMS_CREATE_THREAD_ATTRIBUTES
    PsAttributeMitigationOptions, // in PPS_MITIGATION_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_POLICY_*) // since WIN8
    PsAttributeProtectionLevel, // in PS_PROTECTION // since WINBLUE
    PsAttributeSecureProcess, // in PPS_TRUSTLET_CREATE_ATTRIBUTES, since THRESHOLD
    PsAttributeJobList, // in HANDLE[]
    PsAttributeChildProcessPolicy, // 20, in PULONG (PROCESS_CREATION_CHILD_PROCESS_*) // since THRESHOLD2
    PsAttributeAllApplicationPackagesPolicy, // in PULONG (PROCESS_CREATION_ALL_APPLICATION_PACKAGES_*) // since REDSTONE
    PsAttributeWin32kFilter, // in PWIN32K_SYSCALL_FILTER
    PsAttributeSafeOpenPromptOriginClaim, // in
    PsAttributeBnoIsolation, // in PPS_BNO_ISOLATION_PARAMETERS // since REDSTONE2
    PsAttributeDesktopAppPolicy, // in PULONG (PROCESS_CREATION_DESKTOP_APP_*)
    PsAttributeChpe, // in BOOLEAN // since REDSTONE3
    PsAttributeMitigationAuditOptions, // in PPS_MITIGATION_AUDIT_OPTIONS_MAP (PROCESS_CREATION_MITIGATION_AUDIT_POLICY_*) // since 21H1
    PsAttributeMachineType, // in WORD // since 21H2
    PsAttributeComponentFilter,
    PsAttributeEnableOptionalXStateFeatures, // since WIN11
    PsAttributeMax
} PS_ATTRIBUTE_NUM;

// private
#define PS_ATTRIBUTE_NUMBER_MASK 0x0000ffff
#define PS_ATTRIBUTE_THREAD 0x00010000 // may be used with thread creation
#define PS_ATTRIBUTE_INPUT 0x00020000 // input only
#define PS_ATTRIBUTE_ADDITIVE 0x00040000 // "accumulated" e.g. bitmasks, counters, etc.


#define PsAttributeValue(Number, Thread, Input, Additive) \
    (((Number) & PS_ATTRIBUTE_NUMBER_MASK) | \
    ((Thread) ? PS_ATTRIBUTE_THREAD : 0) | \
    ((Input) ? PS_ATTRIBUTE_INPUT : 0) | \
    ((Additive) ? PS_ATTRIBUTE_ADDITIVE : 0))

#define PS_ATTRIBUTE_IMAGE_NAME \
    PsAttributeValue(PsAttributeImageName, FALSE, TRUE, FALSE)

#define RTL_CONSTANT_STRING(s) { sizeof(s)-sizeof((s)[0]), sizeof(s), s }
typedef VOID     (__stdcall *PIO_APC_ROUTINE)(PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,ULONG Reserved);

typedef VOID     (__stdcall *RtlInitUnicodeString_t)(PUNICODE_STRING DestinationString, PWSTR SourceString);
typedef NTSTATUS (__stdcall *RtlCreateProcessParametersEx_t)(PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,PUNICODE_STRING ImagePathName,PUNICODE_STRING DllPath,PUNICODE_STRING CurrentDirectory,PUNICODE_STRING CommandLine,PVOID Environment,PUNICODE_STRING WindowTitle,PUNICODE_STRING DesktopInfo,PUNICODE_STRING ShellInfo,PUNICODE_STRING RuntimeData,ULONG Flags);
typedef PVOID    (__stdcall *RtlAllocateHeap_t)(PVOID HeapHandle,ULONG Flags,SIZE_T Size);
typedef ULONG    (__stdcall *RtlGetProcessHeaps_t)(ULONG NumberOfHeaps,PVOID* ProcessHeaps);
typedef NTSTATUS (__stdcall *NtCreateUserProcess_t)(PHANDLE ProcessHandle,PHANDLE ThreadHandle,ACCESS_MASK ProcessDesiredAccess,ACCESS_MASK ThreadDesiredAccess,POBJECT_ATTRIBUTES ProcessObjectAttributes,POBJECT_ATTRIBUTES ThreadObjectAttributes,ULONG ProcessFlags,ULONG ThreadFlags,PRTL_USER_PROCESS_PARAMETERS ProcessParameters,PPS_CREATE_INFO CreateInfo,PPS_ATTRIBUTE_LIST AttributeList);
typedef BOOLEAN  (__stdcall *RtlFreeHeap_t)(PVOID HeapHandle,ULONG Flags,PVOID BaseAddress);
typedef NTSTATUS (__stdcall *NtReadFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *NtQueryInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (__stdcall *RtlDestroyProcessParameters_t)(PRTL_USER_PROCESS_PARAMETERS ProcessParameters);
typedef NTSTATUS (__stdcall *NtCreateFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,PLARGE_INTEGER AllocationSize,ULONG FileAttributes,ULONG ShareAccess,ULONG CreateDisposition,ULONG CreateOptions,PVOID EaBuffer,ULONG EaLength);
typedef NTSTATUS (__stdcall *NtWriteFile_t)(HANDLE FileHandle,HANDLE Event,PIO_APC_ROUTINE ApcRoutine,PVOID ApcContext,PIO_STATUS_BLOCK IoStatusBlock,PVOID Buffer,ULONG Length,PLARGE_INTEGER ByteOffset,PULONG Key);
typedef NTSTATUS (__stdcall *NtOpenFile_t)(PHANDLE FileHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,PIO_STATUS_BLOCK IoStatusBlock,ULONG ShareAccess,ULONG OpenOptions);
typedef NTSTATUS (__stdcall *NtClose_t)(HANDLE);
typedef BOOLEAN  (__stdcall *RtlDosPathNameToNtPathName_U_t)(PCWSTR DosFileName,PUNICODE_STRING NtFileName,PWSTR* FilePart,PVOID Reserved);
typedef NTSTATUS (__stdcall *RtlMultiByteToUnicodeN_t)(PWCH UnicodeString,ULONG MaxBytesInUnicodeString,PULONG BytesInUnicodeString,PCSTR MultiByteString,ULONG BytesInMultiByteString);
typedef NTSTATUS (__stdcall *LdrLoadDll_t)(PCWSTR DllPath, PULONG DllCharacteristics, PUNICODE_STRING DllName, PVOID* DllHandle);
typedef NTSTATUS (__stdcall *LdrGetProcedureAddress_t)(PVOID DllHandle, PANSI_STRING ProcedureName, ULONG ProcedureNumber, PVOID* ProcedureAddress);
typedef NTSTATUS (__stdcall *NtAllocateVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, ULONG_PTR ZeroBits, PSIZE_T RegionSize, ULONG AllocationType, ULONG Protect);
typedef NTSTATUS (__stdcall *NtProtectVirtualMemory_t)(HANDLE ProcessHandle, PVOID *BaseAddress, PSIZE_T RegionSize, DWORD NewProtect, PULONG OldProtect);
typedef NTSTATUS (__stdcall *NtFreeVirtualMemory_t)(HANDLE ProcessHandle, PVOID* BaseAddress, PSIZE_T RegionSize, ULONG FreeType);
typedef NTSTATUS (__stdcall *NtWriteVirtualMemory_t)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite,PULONG NumberOfBytesWritten);
typedef NTSTATUS (__stdcall *NtReadVirtualMemory_t)(HANDLE ProcessHandle,PVOID BaseAddress,PVOID Buffer,SIZE_T BufferSize,PSIZE_T NumberOfBytesRead);
typedef NTSTATUS (__stdcall *NtFlushInstructionCache_t)(HANDLE ProcessHandle, PVOID BaseAddress, SIZE_T Length);
typedef NTSTATUS (__stdcall *NtSetInformationFile_t)(HANDLE FileHandle,PIO_STATUS_BLOCK IoStatusBlock,PVOID FileInformation,ULONG Length,FILE_INFORMATION_CLASS FileInformationClass);
typedef NTSTATUS (__stdcall *NtCreateProcess_t)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ParentProcess,BOOLEAN InheritObjectTable,HANDLE SectionHandle,HANDLE DebugPort,HANDLE ExceptionPort);
typedef NTSTATUS (__stdcall *NtCreateProcessEx_t)(PHANDLE ProcessHandle,ACCESS_MASK DesiredAccess,POBJECT_ATTRIBUTES ObjectAttributes,HANDLE ParentProcess,ULONG Flags,HANDLE SectionHandle,HANDLE DebugPort,HANDLE ExceptionPort,BOOLEAN InJob);

typedef struct _PS_STD_HANDLE_INFO
{
    union
    {
        ULONG Flags;
        struct
        {
            ULONG StdHandleState : 2; // PS_STD_HANDLE_STATE
            ULONG PseudoHandleMask : 3; // PS_STD_*
        };
    };
    ULONG StdHandleSubsystemType;
} PS_STD_HANDLE_INFO, *PPS_STD_HANDLE_INFO;


#endif //REVENANT_DEFS_H

