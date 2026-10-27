/*
 * PROJECT: ReactOS Setup Library
 * LICENSE: GPL-2.0-or-later
 * PURPOSE: Install the BIOS UDF VBR after verifying FREELDR.SYS's physical run.
 */
#include "precomp.h"
#include "bootcode.h"
#include "partlist.h"
#include "fsutil.h"
#include <ntddstor.h>
#define NDEBUG
#include <debug.h>

#define UDF_OBJECT_NAME_BUFFER_SIZE 2048

static NTSTATUS UdfReadAt(HANDLE File, ULONGLONG Position, void *Buffer, ULONG Length)
{
    LARGE_INTEGER Offset;
    IO_STATUS_BLOCK IoStatus;
    NTSTATUS Status;
    Offset.QuadPart = Position;
    Status = NtReadFile(File, NULL, NULL, NULL, &IoStatus, Buffer, Length, &Offset, NULL);
    if (NT_SUCCESS(Status) && IoStatus.Information != Length) Status = STATUS_DEVICE_DATA_ERROR;
    return Status;
}

NTSTATUS InstallUdfBootCode(PCWSTR SrcPath, HANDLE RootPartition)
{
    POBJECT_NAME_INFORMATION ObjectName = NULL;
    WCHAR LoaderPath[MAX_PATH];
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    PARTITION_INFORMATION_EX Partition;
    DISK_GEOMETRY Geometry;
    GET_LENGTH_INFORMATION DiskLength;
    STORAGE_DEVICE_NUMBER DiskNumber;
    FILE_STANDARD_INFORMATION FileInfo;
    STARTING_VCN_INPUT_BUFFER Start;
    struct { RETRIEVAL_POINTERS_BUFFER Header; } Runs;
    BOOTCODE Template = {0};
    HANDLE Loader = NULL;
    HANDLE Disk = NULL;
    UCHAR *Buffers = NULL;
    UCHAR Check[512], VolumeSector[512];
    WCHAR DiskPath[64];
    ULONG Returned, SectorCount, Patch = MAXULONG, Index;
    ULONGLONG Lcn, Absolute, Position;
    LARGE_INTEGER Offset;
    NTSTATUS Status;
    PCSTR Stage = "geometry";

    Status = NtDeviceIoControlFile(RootPartition, NULL, NULL, NULL, &IoStatus,
                                   IOCTL_DISK_GET_DRIVE_GEOMETRY, NULL, 0, &Geometry, sizeof(Geometry));
    if (!NT_SUCCESS(Status)) goto Done;
    if (Geometry.BytesPerSector != 512) { Status = STATUS_NOT_SUPPORTED; goto Done; }
    Stage = "partition information";
    Status = NtDeviceIoControlFile(RootPartition, NULL, NULL, NULL, &IoStatus,
                                   IOCTL_DISK_GET_PARTITION_INFO_EX, NULL, 0, &Partition, sizeof(Partition));
    if (!NT_SUCCESS(Status)) goto Done;
    if (Partition.PartitionStyle != PARTITION_STYLE_MBR ||
        Partition.StartingOffset.QuadPart <= 0 || Partition.StartingOffset.QuadPart % 512 ||
        Partition.PartitionLength.QuadPart % 512)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    Stage = "partition object name";
    ObjectName = RtlAllocateHeap(ProcessHeap, 0, UDF_OBJECT_NAME_BUFFER_SIZE);
    if (!ObjectName) { Status = STATUS_NO_MEMORY; goto Done; }
    Status = NtQueryObject(RootPartition, ObjectNameInformation, ObjectName,
                           UDF_OBJECT_NAME_BUFFER_SIZE, &Returned);
    if (!NT_SUCCESS(Status)) goto Done;
    if (ObjectName->Name.Length + sizeof(L"\\freeldr.sys") > sizeof(LoaderPath))
    { Status = STATUS_NAME_TOO_LONG; goto Done; }
    memcpy(LoaderPath, ObjectName->Name.Buffer, ObjectName->Name.Length);
    LoaderPath[ObjectName->Name.Length / sizeof(WCHAR)] = 0;
    Status = RtlStringCchCatW(LoaderPath, ARRAYSIZE(LoaderPath), L"\\freeldr.sys");
    if (!NT_SUCCESS(Status)) goto Done;
    RtlInitUnicodeString(&Name, LoaderPath);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    /* Keep the loader immutable until the VBR is committed. */
    Stage = "open freeldr.sys";
    Status = NtOpenFile(&Loader, FILE_GENERIC_READ | SYNCHRONIZE, &Attributes, &IoStatus,
                        FILE_SHARE_READ, FILE_SYNCHRONOUS_IO_NONALERT | FILE_NON_DIRECTORY_FILE);
    if (!NT_SUCCESS(Status)) goto Done;
    Stage = "freeldr.sys size";
    Status = NtQueryInformationFile(Loader, &IoStatus, &FileInfo, sizeof(FileInfo), FileStandardInformation);
    if (!NT_SUCCESS(Status)) goto Done;
    if (FileInfo.EndOfFile.QuadPart <= 0 || FileInfo.EndOfFile.QuadPart >= 0x98000 - 0xF800)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    SectorCount = (FileInfo.EndOfFile.LowPart + 511) / 512;
    Start.StartingVcn.QuadPart = 0;
    Stage = "freeldr.sys extents";
    Status = NtFsControlFile(Loader, NULL, NULL, NULL, &IoStatus,
                             FSCTL_GET_RETRIEVAL_POINTERS, &Start, sizeof(Start), &Runs, sizeof(Runs));
    if (!NT_SUCCESS(Status)) goto Done;
    if (IoStatus.Information < FIELD_OFFSET(RETRIEVAL_POINTERS_BUFFER, Extents[1]) ||
        Runs.Header.ExtentCount != 1 || Runs.Header.StartingVcn.QuadPart != 0 ||
        Runs.Header.Extents[0].NextVcn.QuadPart < SectorCount ||
        Runs.Header.Extents[0].Lcn.QuadPart < 0)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    Lcn = Runs.Header.Extents[0].Lcn.QuadPart;
    Absolute = (ULONGLONG)Partition.StartingOffset.QuadPart / 512 + Lcn;
    if (Lcn + SectorCount > (ULONGLONG)Partition.PartitionLength.QuadPart / 512 ||
        Absolute + SectorCount > MAXULONG)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    Stage = "flush partition before extent check";
    Status = NtFlushBuffersFile(RootPartition, &IoStatus);
    if (!NT_SUCCESS(Status)) goto Done;
    Buffers = RtlAllocateHeap(ProcessHeap, 0, 2 * 65536);
    if (!Buffers) { Status = STATUS_NO_MEMORY; goto Done; }
    /* Retrieval-pointer units must be physical 512-byte sectors on this volume.
     * Compare every byte through the file and raw partition handles before use. */
    for (Position = 0; Position < (ULONGLONG)FileInfo.EndOfFile.QuadPart; Position += 65536)
    {
        ULONG Count = min(65536ULL, (ULONGLONG)FileInfo.EndOfFile.QuadPart - Position);
        Stage = "read freeldr.sys";
        Status = UdfReadAt(Loader, Position, Buffers, Count);
        if (!NT_SUCCESS(Status)) goto Done;
        Stage = "read freeldr.sys physical extent";
        Status = UdfReadAt(RootPartition, Lcn * 512 + Position, Buffers + 65536, (Count + 511) & ~511UL);
        if (!NT_SUCCESS(Status)) goto Done;
        if (memcmp(Buffers, Buffers + 65536, Count))
        { Status = STATUS_FILE_CORRUPT_ERROR; goto Done; }
    }
    RtlInitUnicodeString(&Name, SrcPath);
    Stage = "read udf.bin";
    Status = ReadBootCodeFromFile(&Template, &Name, 512);
    if (!NT_SUCCESS(Status)) goto Done;
    if (((UCHAR *)Template.BootCode)[510] != 0x55 || ((UCHAR *)Template.BootCode)[511] != 0xaa)
    { Status = STATUS_FILE_CORRUPT_ERROR; goto Done; }
    for (Index = 0; Index <= 512 - 14; ++Index)
    {
        if (memcmp((UCHAR *)Template.BootCode + Index, "UDFSRAW1", 8)) continue;
        if (Patch != MAXULONG || memcmp((UCHAR *)Template.BootCode + Index + 8, "\0\0\0\0\0\0", 6))
        { Status = STATUS_FILE_CORRUPT_ERROR; goto Done; }
        Patch = Index;
    }
    if (Patch == MAXULONG) { Status = STATUS_FILE_CORRUPT_ERROR; goto Done; }
    for (Index = 0; Index < 4; ++Index)
        ((UCHAR *)Template.BootCode)[Patch + 8 + Index] = (UCHAR)(Absolute >> (Index * 8));
    ((UCHAR *)Template.BootCode)[Patch + 12] = SectorCount & 255;
    ((UCHAR *)Template.BootCode)[Patch + 13] = SectorCount >> 8;
    /* Setup may still hold handles on the installed volume, so an exclusive
     * FSCTL_LOCK_VOLUME cannot succeed here. Sector zero is reserved by UDF:
     * commit just that sector through the physical disk, after flushing the
     * volume and verifying the loader's physical extent above. Keep the
     * loader open, denying writers until the VBR is durable. */
    Stage = "resolve physical disk";
    Status = NtDeviceIoControlFile(RootPartition, NULL, NULL, NULL, &IoStatus,
                                   IOCTL_STORAGE_GET_DEVICE_NUMBER, NULL, 0,
                                   &DiskNumber, sizeof(DiskNumber));
    if (!NT_SUCCESS(Status)) goto Done;
    if (DiskNumber.DeviceType != FILE_DEVICE_DISK || DiskNumber.DeviceNumber == MAXULONG)
    { Status = STATUS_NOT_SUPPORTED; goto Done; }
    Status = RtlStringCchPrintfW(DiskPath, ARRAYSIZE(DiskPath),
                                  L"\\Device\\Harddisk%lu\\Partition0", DiskNumber.DeviceNumber);
    if (!NT_SUCCESS(Status)) goto Done;
    RtlInitUnicodeString(&Name, DiskPath);
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Stage = "open physical disk";
    Status = NtOpenFile(&Disk, FILE_GENERIC_READ | FILE_GENERIC_WRITE | SYNCHRONIZE,
                        &Attributes, &IoStatus, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status)) goto Done;
    Stage = "physical disk length";
    Status = NtDeviceIoControlFile(Disk, NULL, NULL, NULL, &IoStatus,
                                   IOCTL_DISK_GET_LENGTH_INFO, NULL, 0,
                                   &DiskLength, sizeof(DiskLength));
    if (!NT_SUCCESS(Status)) goto Done;
    if (Partition.StartingOffset.QuadPart > DiskLength.Length.QuadPart - 512)
    { Status = STATUS_INVALID_PARAMETER; goto Done; }
    Stage = "compare pre-write VBR";
    Status = UdfReadAt(RootPartition, 0, VolumeSector, sizeof(VolumeSector));
    if (!NT_SUCCESS(Status)) goto Done;
    Status = UdfReadAt(Disk, Partition.StartingOffset.QuadPart, Check, sizeof(Check));
    if (!NT_SUCCESS(Status)) goto Done;
    if (memcmp(VolumeSector, Check, sizeof(Check)))
    { Status = STATUS_FILE_CORRUPT_ERROR; goto Done; }
    Offset = Partition.StartingOffset;
    Stage = "write physical VBR";
    Status = NtWriteFile(Disk, NULL, NULL, NULL, &IoStatus, Template.BootCode, 512, &Offset, NULL);
    if (!NT_SUCCESS(Status)) goto Done;
    if (IoStatus.Information != 512) { Status = STATUS_DEVICE_DATA_ERROR; goto Done; }
    Stage = "flush physical VBR";
    Status = NtFlushBuffersFile(Disk, &IoStatus);
    if (!NT_SUCCESS(Status)) goto Done;
    Stage = "read back physical VBR";
    Status = UdfReadAt(Disk, Partition.StartingOffset.QuadPart, Check, sizeof(Check));
    if (NT_SUCCESS(Status) && memcmp(Check, Template.BootCode, sizeof(Check))) Status = STATUS_DEVICE_DATA_ERROR;
    DPRINT1("UDF VBR: loader bytes=%I64d LBA=%I64u sectors=%lu status=%08lx\n",
            FileInfo.EndOfFile.QuadPart, Absolute, SectorCount, Status);
Done:
    if (!NT_SUCCESS(Status)) DPRINT1("UDF VBR failed at %s: %08lx\n", Stage, Status);
    if (Disk) NtClose(Disk);
    if (Buffers) RtlFreeHeap(ProcessHeap, 0, Buffers);
    if (ObjectName) RtlFreeHeap(ProcessHeap, 0, ObjectName);
    if (Loader) NtClose(Loader);
    FreeBootCode(&Template);
    return Status;
}

NTSTATUS InstallUdfBootCodeToDisk(PCWSTR SrcPath, PCWSTR RootPath)
{
    UNICODE_STRING Name;
    OBJECT_ATTRIBUTES Attributes;
    IO_STATUS_BLOCK IoStatus;
    HANDLE Partition = NULL;
    NTSTATUS Status;

    RtlInitUnicodeString(&Name, RootPath);
    while (Name.Length && Name.Buffer[Name.Length / sizeof(WCHAR) - 1] == L'\\')
        Name.Length -= sizeof(WCHAR);
    if (!Name.Length) return STATUS_INVALID_PARAMETER;
    InitializeObjectAttributes(&Attributes, &Name, OBJ_CASE_INSENSITIVE, NULL, NULL);
    Status = NtOpenFile(&Partition, GENERIC_READ | GENERIC_WRITE | SYNCHRONIZE,
                        &Attributes, &IoStatus, FILE_SHARE_READ | FILE_SHARE_WRITE,
                        FILE_SYNCHRONOUS_IO_NONALERT);
    if (!NT_SUCCESS(Status))
    {
        DPRINT1("UDF VBR failed opening %S: %08lx\n", RootPath, Status);
        return Status;
    }
    Status = InstallUdfBootCode(SrcPath, Partition);
    NtClose(Partition);
    return Status;
}
