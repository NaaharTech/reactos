/*
 * Copyright 2026 KosBeg
 * SPDX-License-Identifier: GPL-2.0-or-later
 *
 * Combine contiguous, unpublished directory appends. This is not a general
 * sector writeback cache: overwrites, growth of the physical mapping, retag,
 * write-through and explicit flush first drain the old append range.
 */
#include "udffs.h"

#define UDF_DIR_APPEND_CAPACITY 16384
#define UDF_DIR_APPEND_BUDGET   (1024 * 1024)

typedef struct _UDF_DIR_APPEND_CACHE {
    ERESOURCE Resource;
    int64 Offset;
    ULONG Length;
    int8 Buffer[UDF_DIR_APPEND_CAPACITY];
} UDF_DIR_APPEND_CACHE;

static BOOLEAN
UDFDirectoryAppendAllocated(PVCB Vcb, PUDF_DATALOC_INFO Dloc,
                            int64 Offset, SIZE_T Length)
{
    SIZE_T available;
    uint32 flags, lba;
    while (Length) {
        lba = UDFExtentOffsetToLba(Vcb, Dloc->DataLoc.Mapping, Offset,
                                  NULL, &available, &flags, NULL);
        if (lba == LBA_OUT_OF_EXTENT || !available ||
            (flags != EXTENT_RECORDED_ALLOCATED &&
             flags != EXTENT_NOT_RECORDED_ALLOCATED))
            return FALSE;
        available = min(available, Length);
        Offset += available;
        Length -= available;
    }
    return TRUE;
}

static UDF_DIR_APPEND_CACHE*
UDFAllocateDirectoryAppend(PVCB Vcb, PUDF_DATALOC_INFO Dloc)
{
    LONG used;
    UDF_DIR_APPEND_CACHE* cache;

    if (Dloc->DirectoryAppend)
        return Dloc->DirectoryAppend;
    do {
        used = InterlockedCompareExchange(&Vcb->DirectoryAppendBytes, 0, 0);
        if (used > UDF_DIR_APPEND_BUDGET - UDF_DIR_APPEND_CAPACITY)
            return NULL;
    } while (InterlockedCompareExchange(&Vcb->DirectoryAppendBytes,
                used + UDF_DIR_APPEND_CAPACITY, used) != used);
    cache = MyAllocatePool__(NonPagedPool, sizeof(*cache));
    if (!cache) {
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes, -UDF_DIR_APPEND_CAPACITY);
        return NULL;
    }
    RtlZeroMemory(cache, sizeof(*cache));
    if (!NT_SUCCESS(ExInitializeResourceLite(&cache->Resource))) {
        MyFreePool__(cache);
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes, -UDF_DIR_APPEND_CAPACITY);
        return NULL;
    }
    /* Existing directory/VCB resource ownership serializes publication. The
     * cache resource also protects reader snapshots and short-I/O retries. */
    Dloc->DirectoryAppend = cache;
    return cache;
}

BOOLEAN
UDFDirectoryAppendPending(PUDF_FILE_INFO FileInfo)
{
    UDF_DIR_APPEND_CACHE* cache;
    BOOLEAN pending;
    if (!FileInfo || !FileInfo->Dloc ||
        !(cache = FileInfo->Dloc->DirectoryAppend))
        return FALSE;
    UDFAcquireResourceShared(&cache->Resource, TRUE);
    pending = cache->Length != 0;
    UDFReleaseResource(&cache->Resource);
    return pending;
}

NTSTATUS
UDFFlushDirectoryAppend(PIRP_CONTEXT IrpContext, PVCB Vcb,
                        PUDF_FILE_INFO FileInfo)
{
    UDF_DIR_APPEND_CACHE* cache = FileInfo->Dloc->DirectoryAppend;
    NTSTATUS status = STATUS_SUCCESS;
    SIZE_T written = 0;
    if (!cache)
        return STATUS_SUCCESS;
    UDFAcquireResourceExclusive(&cache->Resource, TRUE);
    if (cache->Length) {
        status = UDFWriteExtent(IrpContext, Vcb, &FileInfo->Dloc->DataLoc,
                    cache->Offset, cache->Length, FALSE, cache->Buffer, &written);
        if (NT_SUCCESS(status) && written != cache->Length)
            status = STATUS_IO_DEVICE_ERROR;
        if (NT_SUCCESS(status)) {
            cache->Length = 0;
        } else {
            /* Keep the complete generation, including a possibly written
             * prefix. Retrying it is idempotent on the unchanged mapping. */
            FileInfo->Dloc->DataLoc.Modified = TRUE;
            FileInfo->Dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
        }
    }
    UDFReleaseResource(&cache->Resource);
    return status;
}

NTSTATUS
UDFTryDirectoryAppend(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO FileInfo, int64 Offset, SIZE_T Length, BOOLEAN Direct,
    int8* Buffer, PSIZE_T WrittenBytes, PBOOLEAN Handled)
{
    PUDF_DATALOC_INFO dloc = FileInfo->Dloc;
    UDF_DIR_APPEND_CACHE* cache = dloc->DirectoryAppend;
    PFILE_OBJECT fileObject = NULL;
    NTSTATUS status;
    BOOLEAN eligible = FALSE;
    int64 allocated;

    *Handled = FALSE;
    if (!dloc->DirIndex && !cache)
        return STATUS_SUCCESS;
    if (IrpContext->Irp)
        fileObject = IoGetCurrentIrpStackLocation(IrpContext->Irp)->FileObject;
    allocated = dloc->DataLoc.Mapping ? UDFGetExtentLength(dloc->DataLoc.Mapping) : 0;
    if (!Direct && Length >= sizeof(FILE_IDENT_DESC) &&
        Length <= UDF_DIR_APPEND_CAPACITY && Buffer && Offset >= 0 &&
        (uint64)Offset <= MAXLONGLONG - (uint64)Length &&
        Offset == dloc->DataLoc.Length &&
        dloc->DirectoryCommitKnown && Offset >= dloc->DirectoryCommittedLength &&
        (uint64)Offset + Length <= (uint64)allocated &&
        dloc->DirIndex && !dloc->DataLoc.Offset &&
        !(dloc->DirIndex->DIFlags & UDF_DI_FLAG_INIT_IN_ICB) &&
        FileInfo->Fcb && dloc->CommonFcb == FileInfo->Fcb &&
        FlagOn(FileInfo->Fcb->FcbState, FCB_STATE_IN_FCB_TABLE) &&
        Vcb->VcbCondition == VcbMounted && !Vcb->CDR_Mode &&
        Vcb->SectorSize == 512 &&
        (Vcb->UdfRevision == 0x201 || Vcb->UdfRevision == 0x250) &&
        Vcb->TargetDeviceObject->DeviceType == FILE_DEVICE_DISK &&
        !FlagOn(Vcb->VcbState, VCB_STATE_VOLUME_READ_ONLY | UDF_VCB_FLAGS_DEAD) &&
        IrpContext->MajorFunction == IRP_MJ_CLEANUP && fileObject &&
        FlagOn(fileObject->Flags, FO_CACHE_SUPPORTED) &&
        !FlagOn(fileObject->Flags, FO_WRITE_THROUGH) &&
        !FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH) &&
        ((PFILE_IDENT_DESC)Buffer)->descTag.tagIdent == TID_FILE_IDENT_DESC &&
        !(((PFILE_IDENT_DESC)Buffer)->fileCharacteristics & (FILE_DELETED | FILE_PARENT)) &&
        UDFDirectoryAppendAllocated(Vcb, dloc, Offset, Length)) {
        eligible = TRUE;
    }
    if (cache) {
        UDFAcquireResourceShared(&cache->Resource, TRUE);
        if (cache->Length && (!eligible ||
            cache->Offset + cache->Length != Offset ||
            Length > UDF_DIR_APPEND_CAPACITY - cache->Length)) {
            UDFReleaseResource(&cache->Resource);
            status = UDFFlushDirectoryAppend(IrpContext, Vcb, FileInfo);
            if (!NT_SUCCESS(status))
                return status;
        } else {
            UDFReleaseResource(&cache->Resource);
        }
    }
    if (!eligible)
        return STATUS_SUCCESS;
    status = UDFOpenIntegrityForWrite(IrpContext, Vcb, FALSE);
    if (!NT_SUCCESS(status))
        return status;
    if (!cache && !(cache = UDFAllocateDirectoryAppend(Vcb, dloc)))
        return STATUS_SUCCESS; // Memory/budget failure preserves the old I/O path.

    UDFAcquireResourceExclusive(&cache->Resource, TRUE);
    if (!cache->Length)
        cache->Offset = Offset;
    ASSERT(cache->Offset + cache->Length == Offset);
    ASSERT(Length <= UDF_DIR_APPEND_CAPACITY - cache->Length);
    RtlCopyMemory(cache->Buffer + cache->Length, Buffer, Length);
    cache->Length += (ULONG)Length;
    UDFSetFileSize(FileInfo, Offset + Length);
    dloc->DataLoc.Length = Offset + Length;
    dloc->DataLoc.Modified = TRUE;
    dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
    *WrittenBytes = Length;
    *Handled = TRUE;
    UDFReleaseResource(&cache->Resource);
    return STATUS_SUCCESS;
}

NTSTATUS
UDFReadDirectoryAppend(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO FileInfo, int64 Offset, SIZE_T Length, BOOLEAN Direct,
    int8* Buffer)
{
    UDF_DIR_APPEND_CACHE* cache = FileInfo->Dloc->DirectoryAppend;
    NTSTATUS status = STATUS_SUCCESS;
    int64 end, first, last;
    SIZE_T prefix, middle;
    if (Offset < 0 || (uint64)Length > MAXLONGLONG - (uint64)Offset)
        return STATUS_INVALID_PARAMETER;
    end = Offset + Length;
    UDFAcquireResourceShared(&cache->Resource, TRUE);
    first = max(Offset, cache->Offset);
    last = min(end, cache->Offset + cache->Length);
    if (!cache->Length || first >= last) {
        status = UDFReadExtent(IrpContext, Vcb, &FileInfo->Dloc->DataLoc,
                               Offset, Length, Direct, Buffer);
    } else {
        prefix = (SIZE_T)(first - Offset);
        middle = (SIZE_T)(last - first);
        if (prefix)
            status = UDFReadExtent(IrpContext, Vcb, &FileInfo->Dloc->DataLoc,
                                   Offset, prefix, Direct, Buffer);
        if (NT_SUCCESS(status)) {
            RtlCopyMemory(Buffer + prefix, cache->Buffer + first - cache->Offset, middle);
            if (last < end)
                status = UDFReadExtent(IrpContext, Vcb, &FileInfo->Dloc->DataLoc,
                            last, (SIZE_T)(end - last), Direct, Buffer + prefix + middle);
        }
    }
    UDFReleaseResource(&cache->Resource);
    return status;
}

BOOLEAN
UDFReleaseDirectoryAppend(PVCB Vcb, PUDF_DATALOC_INFO Dloc)
{
    UDF_DIR_APPEND_CACHE* cache = Dloc->DirectoryAppend;
    if (!cache)
        return TRUE;
    /* Normal teardown flushed before removing the FCB/LCBs. Never discard a
     * failed dirty generation merely because its last handle was closed. */
    if (cache->Length) {
        return FALSE;
    }
    ExDeleteResourceLite(&cache->Resource);
    MyFreePool__(cache);
    Dloc->DirectoryAppend = NULL;
    InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes, -UDF_DIR_APPEND_CAPACITY);
    return TRUE;
}
