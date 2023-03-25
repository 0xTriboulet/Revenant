#ifndef REVENANT_STRUCTS_H
#define REVENANT_STRUCTS_H

#define InitializeObjectAttributes( p, n, a, r, s ) {   \
    (p)->Length = sizeof( OBJECT_ATTRIBUTES );          \
    (p)->RootDirectory = r;                             \
    (p)->Attributes = a;                                \
    (p)->ObjectName = n;                                \
    (p)->SecurityDescriptor = s;                        \
    (p)->SecurityQualityOfService = NULL;               \
    }

typedef struct _FILE_STANDARD_INFORMATION {
    LARGE_INTEGER AllocationSize;
    LARGE_INTEGER EndOfFile;
    ULONG NumberOfLinks;
    BOOLEAN DeletePending;
    BOOLEAN Directory;
} FILE_STANDARD_INFORMATION, *PFILE_STANDARD_INFORMATION;

typedef struct _UNICODE_STRING {
    USHORT              Length;
    USHORT              MaximumLength;
    PWSTR               Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

typedef struct _IO_STATUS_BLOCK {
    union {
        NTSTATUS Status;
        PVOID Pointer;
    } DUMMYUNIONNAME;
    ULONG_PTR Information;
} IO_STATUS_BLOCK, *PIO_STATUS_BLOCK;

typedef enum _FILE_INFORMATION_CLASS {
    FileDirectoryInformation = 1, // FILE_DIRECTORY_INFORMATION
    FileFullDirectoryInformation, // FILE_FULL_DIR_INFORMATION
    FileBothDirectoryInformation, // FILE_BOTH_DIR_INFORMATION
    FileBasicInformation, // FILE_BASIC_INFORMATION
    FileStandardInformation, // FILE_STANDARD_INFORMATION
    FileInternalInformation, // FILE_INTERNAL_INFORMATION
    FileEaInformation, // FILE_EA_INFORMATION
    FileAccessInformation, // FILE_ACCESS_INFORMATION
    FileNameInformation, // FILE_NAME_INFORMATION
    FileRenameInformation, // FILE_RENAME_INFORMATION // 10
    FileLinkInformation, // FILE_LINK_INFORMATION
    FileNamesInformation, // FILE_NAMES_INFORMATION
    FileDispositionInformation, // FILE_DISPOSITION_INFORMATION
    FilePositionInformation, // FILE_POSITION_INFORMATION
    FileFullEaInformation, // FILE_FULL_EA_INFORMATION
    FileModeInformation, // FILE_MODE_INFORMATION
    FileAlignmentInformation, // FILE_ALIGNMENT_INFORMATION
    FileAllInformation, // FILE_ALL_INFORMATION
    FileAllocationInformation, // FILE_ALLOCATION_INFORMATION
    FileEndOfFileInformation, // FILE_END_OF_FILE_INFORMATION // 20
    FileAlternateNameInformation, // FILE_NAME_INFORMATION
    FileStreamInformation, // FILE_STREAM_INFORMATION
    FilePipeInformation, // FILE_PIPE_INFORMATION
    FilePipeLocalInformation, // FILE_PIPE_LOCAL_INFORMATION
    FilePipeRemoteInformation, // FILE_PIPE_REMOTE_INFORMATION
    FileMailslotQueryInformation, // FILE_MAILSLOT_QUERY_INFORMATION
    FileMailslotSetInformation, // FILE_MAILSLOT_SET_INFORMATION
    FileCompressionInformation, // FILE_COMPRESSION_INFORMATION
    FileObjectIdInformation, // FILE_OBJECTID_INFORMATION
    FileCompletionInformation, // FILE_COMPLETION_INFORMATION // 30
    FileMoveClusterInformation, // FILE_MOVE_CLUSTER_INFORMATION
    FileQuotaInformation, // FILE_QUOTA_INFORMATION
    FileReparsePointInformation, // FILE_REPARSE_POINT_INFORMATION
    FileNetworkOpenInformation, // FILE_NETWORK_OPEN_INFORMATION
    FileAttributeTagInformation, // FILE_ATTRIBUTE_TAG_INFORMATION
    FileTrackingInformation, // FILE_TRACKING_INFORMATION
    FileIdBothDirectoryInformation, // FILE_ID_BOTH_DIR_INFORMATION
    FileIdFullDirectoryInformation, // FILE_ID_FULL_DIR_INFORMATION
    FileValidDataLengthInformation, // FILE_VALID_DATA_LENGTH_INFORMATION
    FileShortNameInformation, // FILE_NAME_INFORMATION // 40
    FileIoCompletionNotificationInformation, // FILE_IO_COMPLETION_NOTIFICATION_INFORMATION // since VISTA
    FileIoStatusBlockRangeInformation, // FILE_IOSTATUSBLOCK_RANGE_INFORMATION
    FileIoPriorityHintInformation, // FILE_IO_PRIORITY_HINT_INFORMATION
    FileSfioReserveInformation, // FILE_SFIO_RESERVE_INFORMATION
    FileSfioVolumeInformation, // FILE_SFIO_VOLUME_INFORMATION
    FileHardLinkInformation, // FILE_LINKS_INFORMATION
    FileProcessIdsUsingFileInformation, // FILE_PROCESS_IDS_USING_FILE_INFORMATION
    FileNormalizedNameInformation, // FILE_NAME_INFORMATION
    FileNetworkPhysicalNameInformation, // FILE_NETWORK_PHYSICAL_NAME_INFORMATION
    FileIdGlobalTxDirectoryInformation, // FILE_ID_GLOBAL_TX_DIR_INFORMATION // since WIN7 // 50
    FileIsRemoteDeviceInformation, // FILE_IS_REMOTE_DEVICE_INFORMATION
    FileUnusedInformation,
    FileNumaNodeInformation, // FILE_NUMA_NODE_INFORMATION
    FileStandardLinkInformation, // FILE_STANDARD_LINK_INFORMATION
    FileRemoteProtocolInformation, // FILE_REMOTE_PROTOCOL_INFORMATION
    FileRenameInformationBypassAccessCheck, // (kernel-mode only); FILE_RENAME_INFORMATION // since WIN8
    FileLinkInformationBypassAccessCheck, // (kernel-mode only); FILE_LINK_INFORMATION
    FileVolumeNameInformation, // FILE_VOLUME_NAME_INFORMATION
    FileIdInformation, // FILE_ID_INFORMATION
    FileIdExtdDirectoryInformation, // FILE_ID_EXTD_DIR_INFORMATION
    FileReplaceCompletionInformation, // FILE_COMPLETION_INFORMATION // since WINBLUE
    FileHardLinkFullIdInformation, // FILE_LINK_ENTRY_FULL_ID_INFORMATION
    FileIdExtdBothDirectoryInformation, // FILE_ID_EXTD_BOTH_DIR_INFORMATION // since THRESHOLD
    FileDispositionInformationEx, // FILE_DISPOSITION_INFO_EX // since REDSTONE
    FileRenameInformationEx,
    FileRenameInformationExBypassAccessCheck,
    FileDesiredStorageClassInformation, // FILE_DESIRED_STORAGE_CLASS_INFORMATION // since REDSTONE2
    FileStatInformation, // FILE_STAT_INFORMATION
    FileMaximumInformation
} FILE_INFORMATION_CLASS, *PFILE_INFORMATION_CLASS;



#endif //REVENANT_STRUCTS_H


