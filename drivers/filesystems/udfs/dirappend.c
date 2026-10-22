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
    ULONG Capacity;
    int8* Buffer;
    BOOLEAN InlineOwned;
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

#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
#define UDF_DIR_STAT(Vcb, Index) InterlockedIncrement(&(Vcb)->DirectoryAppendDiag[Index])
static VOID
UDFDirectoryAppendPeak(PVCB Vcb, ULONG Index, LONG Value)
{
    LONG old;
    do {
        old = InterlockedCompareExchange(&Vcb->DirectoryAppendDiag[Index],0,0);
        if (old >= Value)
            break;
    } while (InterlockedCompareExchange(&Vcb->DirectoryAppendDiag[Index],Value,old) != old);
}
#else
#define UDF_DIR_STAT(Vcb, Index) ((void)0)
#endif

static BOOLEAN
UDFChargeDirectoryAppend(PVCB Vcb, LONG Bytes)
{
    LONG used;
    ASSERT(Bytes > 0 && Bytes <= UDF_DIR_APPEND_BUDGET);
    do {
        used = InterlockedCompareExchange(&Vcb->DirectoryAppendBytes,0,0);
        if (used < 0 || used > UDF_DIR_APPEND_BUDGET - Bytes) {
            UDF_DIR_STAT(Vcb,6);
            return FALSE;
        }
    } while (InterlockedCompareExchange(&Vcb->DirectoryAppendBytes,used+Bytes,used) != used);
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    UDFDirectoryAppendPeak(Vcb,2,used+Bytes);
#endif
    return TRUE;
}

static UDF_DIR_APPEND_CACHE*
UDFAllocateDirectoryAppend(PVCB Vcb, PUDF_DATALOC_INFO Dloc)
{
    UDF_DIR_APPEND_CACHE* cache;
    if (Dloc->DirectoryAppend)
        return Dloc->DirectoryAppend;
    if (!UDFChargeDirectoryAppend(Vcb,sizeof(*cache)))
        return NULL;
    cache = MyAllocatePool__(NonPagedPool,sizeof(*cache));
    if (!cache) {
        UDF_DIR_STAT(Vcb,5);
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)sizeof(*cache));
        return NULL;
    }
    RtlZeroMemory(cache,sizeof(*cache));
    if (!NT_SUCCESS(ExInitializeResourceLite(&cache->Resource))) {
        UDF_DIR_STAT(Vcb,5);
        MyFreePool__(cache);
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)sizeof(*cache));
        return NULL;
    }
    /* Keep the control/resource alive until the same Dloc teardown as before:
     * a reader may already have captured its address before taking shared.
     * Only the payload may be returned under this resource's exclusive lock. */
    Dloc->DirectoryAppend = cache;
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    UDFDirectoryAppendPeak(Vcb,8,InterlockedIncrement(&Vcb->DirectoryAppendDiag[7]));
#endif
    return cache;
}

/* Grow only the resident unpublished payload. The old complete generation
 * remains owned if charge/allocation fails. Charge the FULL new allocation
 * while the old buffer is still live, so even resize's temporary storage
 * respects the existing volume-wide budget. Caller holds cache exclusive. */
static BOOLEAN
UDFEnsureDirectoryAppendBuffer(PVCB Vcb, UDF_DIR_APPEND_CACHE* Cache,
                              ULONG Required)
{
    ULONG capacity;
    int8* buffer;
    ASSERT(Required && Required <= UDF_DIR_APPEND_CAPACITY);
    ASSERT(Cache->Length <= Cache->Capacity);
    if (!Required || Required > UDF_DIR_APPEND_CAPACITY)
        return FALSE;
    if (Cache->Buffer && Required <= Cache->Capacity)
        return TRUE;
    capacity = Cache->Capacity ? Cache->Capacity : 512;
    while (capacity < Required)
        capacity *= 2;
    if (!UDFChargeDirectoryAppend(Vcb, (LONG)capacity))
        return FALSE;
    buffer = MyAllocatePool__(NonPagedPool, capacity);
    if (!buffer) {
        UDF_DIR_STAT(Vcb,5);
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)capacity);
        return FALSE;
    }
    if (Cache->Length)
        RtlCopyMemory(buffer, Cache->Buffer, Cache->Length);
    if (Cache->Buffer) {
        MyFreePool__(Cache->Buffer);
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)Cache->Capacity);
        UDF_DIR_STAT(Vcb,4);
    }
    Cache->Buffer = buffer;
    Cache->Capacity = capacity;
    UDF_DIR_STAT(Vcb,3);
    return TRUE;
}

static VOID
UDFReturnDirectoryAppendBuffer(PVCB Vcb, UDF_DIR_APPEND_CACHE* Cache)
{
    ASSERT(!Cache->Length);
    if (Cache->Buffer) {
        MyFreePool__(Cache->Buffer);
        Cache->Buffer = NULL;
        InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)Cache->Capacity);
        Cache->Capacity = 0;
        UDF_DIR_STAT(Vcb,4);
    }
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
    pending = cache->Length != 0 || cache->InlineOwned;
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
            UDFReturnDirectoryAppendBuffer(Vcb,cache);
        } else {
            UDF_DIR_STAT(Vcb,15);
            /* Keep the complete generation, including a possibly written
             * prefix. Retrying it is idempotent on the unchanged mapping. */
            FileInfo->Dloc->DataLoc.Modified = TRUE;
            FileInfo->Dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
        }
    }
    UDFReleaseResource(&cache->Resource);
    return status;
}

/* Only the complete, successful parent FE write releases an inline
 * generation. A failed payload or FE write must keep the Dloc owner. */
VOID
UDFDirectoryAppendFECommitted(PUDF_FILE_INFO FileInfo)
{
    UDF_DIR_APPEND_CACHE* cache = FileInfo->Dloc->DirectoryAppend;
    if (!cache)
        return;
    UDFAcquireResourceExclusive(&cache->Resource, TRUE);
    ASSERT(!cache->Length);
    if (!cache->Length)
        cache->InlineOwned = FALSE;
    UDFReleaseResource(&cache->Resource);
}

/* Only FE-before-FID publication may buffer an overwrite in the suffix
 * beyond the last committed parent FE. Those bytes are not yet reachable
 * through that on-disk FE. The canonical Dloc owns the complete range and
 * every parent-FE writer drains it before advancing the committed boundary.
 * This permits sequential publication after an older tombstone buffer was
 * already materialized; it does not cache overwrites of committed names.
 * No equality assumption or extra disk read is involved.
 */
static BOOLEAN
UDFMayBufferUnpublishedFids(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO Directory, int64 Offset, SIZE_T Length, int8* Buffer)
{
    PUDF_DATALOC_INFO dloc = Directory->Dloc;
    SIZE_T at = 0, size;
    PFILE_IDENT_DESC fid;
    if (!Buffer || Length < sizeof(FILE_IDENT_DESC) ||
        Length > UDF_DIR_APPEND_CAPACITY || Offset < 0 ||
        !FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_PUBLISH) ||
        FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH) ||
        !dloc->DirectoryCommitKnown || dloc->DirectoryCommittedLength < 0 ||
        dloc->DataLoc.Length < 0 || Offset < dloc->DirectoryCommittedLength ||
        (uint64)Offset > (uint64)dloc->DataLoc.Length ||
        Length > (uint64)dloc->DataLoc.Length - (uint64)Offset ||
        !Directory->Fcb || dloc->CommonFcb != Directory->Fcb ||
        Directory->Fcb->FileInfo != Directory || Directory->Fcb->FcbReference <= 0 ||
        !FlagOn(Directory->Fcb->FcbState, FCB_STATE_IN_FCB_TABLE) ||
        FlagOn(Directory->Fcb->FcbState, UDF_FCB_DELETED | UDF_FCB_DELETE_ON_CLOSE))
        return FALSE;
    /* The context flag is set only after scalar FE commit or after the
     * complete volume cohort. Check every incoming complete ordinary FID. */
    while (at < Length) {
        if (Length - at < sizeof(FILE_IDENT_DESC))
            return FALSE;
        fid = (PFILE_IDENT_DESC)(Buffer + at);
        size = (sizeof(FILE_IDENT_DESC) + fid->lengthOfImpUse +
                fid->lengthFileIdent + 3) & ~((SIZE_T)3);
        if (size > Length - at || fid->descTag.tagIdent != TID_FILE_IDENT_DESC ||
            fid->descTag.descCRCLength != size - sizeof(tag) ||
            fid->fileVersionNum != 1 || fid->fileCharacteristics != 0 ||
            !fid->lengthFileIdent || fid->icb.extLength != Vcb->SectorSize ||
            fid->icb.extLocation.partitionReferenceNum >= Vcb->PartitionMaps)
            return FALSE;
        at += size;
    }
    return at == Length;
}

static NTSTATUS
UDFTryDirectoryAppendInternal(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO FileInfo, int64 Offset, SIZE_T Length, BOOLEAN Direct,
    int8* Buffer, PSIZE_T WrittenBytes, PBOOLEAN Handled,
    BOOLEAN ReserveTombstone)
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
    /* DataLoc.Offset describes the current storage. INIT_IN_ICB retains
     * the previous tag mode until retag; it does not make a fully allocated
     * external append an overwrite. Drain payload before retag and FE/AD
     * publication, preserving that tag transition and all retry state. */
    if (!Direct && Length >= sizeof(FILE_IDENT_DESC) &&
        Length <= UDF_DIR_APPEND_CAPACITY && Buffer && Offset >= 0 &&
        (uint64)Offset <= MAXLONGLONG - (uint64)Length &&
        (Offset == dloc->DataLoc.Length ||
         (!ReserveTombstone && UDFMayBufferUnpublishedFids(IrpContext, Vcb,
                                   FileInfo, Offset, Length, Buffer))) &&
        dloc->DirectoryCommitKnown && Offset >= dloc->DirectoryCommittedLength &&
        (uint64)Offset + Length <= (uint64)allocated &&
        dloc->DirIndex && !dloc->DataLoc.Offset &&
        FileInfo->Fcb && dloc->CommonFcb == FileInfo->Fcb &&
        FlagOn(FileInfo->Fcb->FcbState, FCB_STATE_IN_FCB_TABLE) &&
        Vcb->VcbCondition == VcbMounted && !Vcb->CDR_Mode &&
        Vcb->SectorSize == 512 &&
        (Vcb->UdfRevision == 0x201 || Vcb->UdfRevision == 0x250) &&
        Vcb->TargetDeviceObject->DeviceType == FILE_DEVICE_DISK &&
        !FlagOn(Vcb->VcbState, VCB_STATE_VOLUME_READ_ONLY | UDF_VCB_FLAGS_DEAD) &&
        (ReserveTombstone ||
         (IrpContext->MajorFunction == IRP_MJ_CLEANUP && fileObject &&
          FlagOn(fileObject->Flags, FO_CACHE_SUPPORTED) &&
          !FlagOn(fileObject->Flags, FO_WRITE_THROUGH)) ||
         FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_PUBLISH)) &&
        !FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH) &&
        ((PFILE_IDENT_DESC)Buffer)->descTag.tagIdent == TID_FILE_IDENT_DESC &&
        (ReserveTombstone ||
         !(((PFILE_IDENT_DESC)Buffer)->fileCharacteristics & (FILE_DELETED | FILE_PARENT))) &&
        UDFDirectoryAppendAllocated(Vcb, dloc, Offset, Length)) {
        eligible = TRUE;
        UDF_DIR_STAT(Vcb,9);
    }
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    /* Reasons sampled only for complete directory-FID requests. These are
     * admission diagnostics, not an exclusive classification of all writes. */
    else if (dloc->DirIndex && Buffer && Length >= sizeof(FILE_IDENT_DESC) &&
             ((PFILE_IDENT_DESC)Buffer)->descTag.tagIdent == TID_FILE_IDENT_DESC) {
        if (dloc->DataLoc.Offset)
            UDF_DIR_STAT(Vcb,11);
        else if (dloc->DirIndex->DIFlags & UDF_DI_FLAG_INIT_IN_ICB)
            UDF_DIR_STAT(Vcb,10);
        else if (Offset != dloc->DataLoc.Length)
            UDF_DIR_STAT(Vcb,12);
        else if (Offset >= 0 && (uint64)Offset <= MAXLONGLONG - (uint64)Length &&
                 (uint64)Offset + Length > (uint64)allocated)
            UDF_DIR_STAT(Vcb,13);
    }
#endif
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
    if (!UDFEnsureDirectoryAppendBuffer(Vcb, cache,
                                       cache->Length + (ULONG)Length)) {
        UDFReleaseResource(&cache->Resource);
        /* A failed resize keeps the old payload intact. Materialize it
         * before scalar fallback can change the surrounding mapping/data.
         * A failed drain retains ownership and is propagated, not hidden. */
        return UDFFlushDirectoryAppend(IrpContext, Vcb, FileInfo);
    }
    if (!cache->Length)
        cache->Offset = Offset;
    ASSERT(cache->Offset + cache->Length == Offset);
    ASSERT(Length <= UDF_DIR_APPEND_CAPACITY - cache->Length);
    RtlCopyMemory(cache->Buffer + cache->Length, Buffer, Length);
    cache->Length += (ULONG)Length;
    if ((uint64)Offset + Length > (uint64)dloc->DataLoc.Length) {
        UDFSetFileSize(FileInfo, Offset + Length);
        dloc->DataLoc.Length = Offset + Length;
    }
    dloc->DataLoc.Modified = TRUE;
    dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
    *WrittenBytes = Length;
    *Handled = TRUE;
    UDF_DIR_STAT(Vcb,14);
    UDFReleaseResource(&cache->Resource);
    return STATUS_SUCCESS;
}

NTSTATUS
UDFTryDirectoryAppend(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO FileInfo, int64 Offset, SIZE_T Length, BOOLEAN Direct,
    int8* Buffer, PSIZE_T WrittenBytes, PBOOLEAN Handled)
{
    return UDFTryDirectoryAppendInternal(IrpContext, Vcb, FileInfo, Offset,
        Length, Direct, Buffer, WrittenBytes, Handled, FALSE);
}

/* Extend an ordinary directory reservation by at most one sector. The
 * canonical parent owns the complete reference-free FID before allocation;
 * after checked one-sector allocation its tag uses the new mapping.
 * Every parent FE writer drains this generation before exposing the length.
 * The caller holds the same parent FCB as the existing append path.
 */
static NTSTATUS
UDFGrowReservedDirectoryFid(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO Directory, int64 Offset, SIZE_T Length, int8* Buffer,
    PSIZE_T WrittenBytes, PBOOLEAN Handled)
{
    PUDF_DATALOC_INFO dloc = Directory->Dloc;
    UDF_DIR_APPEND_CACHE* cache = dloc->DirectoryAppend;
    int64 allocated = dloc->DataLoc.Mapping ?
                          UDFGetExtentLength(dloc->DataLoc.Mapping) : 0;
    NTSTATUS status;
    EXTENT_INFO extra;
    PEXTENT_MAP newMap;
    uint32 part, lba, mapBytes;
    BOOLEAN ownsRange;

    if (FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH) ||
        dloc->DataLoc.Offset || Offset < 0 ||
        Offset != dloc->DataLoc.Length || allocated <= 0 ||
        !dloc->DirectoryCommitKnown ||
        dloc->DirectoryCommittedLength < 0 ||
        Offset < dloc->DirectoryCommittedLength || allocated < Offset ||
        (uint64)Offset > MAXLONGLONG - (uint64)Length ||
        (uint64)Offset + Length <= (uint64)allocated ||
        (uint64)Offset + Length - (uint64)allocated > Vcb->SectorSize ||
        (Offset < allocated && !UDFDirectoryAppendAllocated(Vcb, dloc, Offset,
                                            (SIZE_T)(allocated - Offset))))
        return STATUS_SUCCESS;
    part = UDFGetRefPartNumByPhysLba(Vcb, dloc->FELoc.Mapping[0].extLocation);
    if (part >= Vcb->PartitionMaps)
        return STATUS_FILE_CORRUPT_ERROR;
    if (!cache && !(cache = UDFAllocateDirectoryAppend(Vcb, dloc)))
        return STATUS_SUCCESS;
    /* The ordinary append gate drained an incompatible previous range.
     * Own retry storage before changing allocation. No FID is written
     * while its final tag address is still unknown. */
    UDFAcquireResourceExclusive(&cache->Resource, TRUE);
    ASSERT(!cache->Length);
    if (cache->Length) {
        UDFReleaseResource(&cache->Resource);
        return STATUS_FILE_CORRUPT_ERROR;
    }
    if (!UDFEnsureDirectoryAppendBuffer(Vcb, cache, (ULONG)Length)) {
        UDFReleaseResource(&cache->Resource);
        return STATUS_SUCCESS;
    }
    RtlCopyMemory(cache->Buffer, Buffer, Length);
    UDFReleaseResource(&cache->Resource);

    mapBytes = UDFGetMappingLength(dloc->DataLoc.Mapping);
    if (mapBytes < 2 * sizeof(EXTENT_MAP) ||
        mapBytes > MAXULONG - sizeof(EXTENT_MAP)) {
        status = STATUS_FILE_CORRUPT_ERROR;
    } else {
        newMap = MyAllocatePool__(NonPagedPool, mapBytes + sizeof(EXTENT_MAP));
        if (!newMap) {
            /* No allocation or namespace change has happened yet. */
            UDFAcquireResourceExclusive(&cache->Resource, TRUE);
            UDFReturnDirectoryAppendBuffer(Vcb, cache);
            UDFReleaseResource(&cache->Resource);
            return STATUS_SUCCESS;
        }
        RtlZeroMemory(&extra, sizeof(extra));
        status = UDFOpenIntegrityForWrite(IrpContext, Vcb, FALSE);
        if (NT_SUCCESS(status))
            status = UDFAllocFreeExtent(IrpContext, Vcb, Vcb->SectorSize,
                        UDFPartStart(Vcb, part), UDFPartEnd(Vcb, part),
                        &extra, dloc->DataLoc.Flags);
        if (NT_SUCCESS(status) && (!extra.Mapping || extra.Offset ||
            extra.Length != Vcb->SectorSize ||
            UDFGetExtentLength(extra.Mapping) != Vcb->SectorSize ||
            extra.Mapping[1].extLength ||
            (extra.Mapping[0].extLength >> 30) > EXTENT_NOT_RECORDED_ALLOCATED))
            status = STATUS_FILE_CORRUPT_ERROR;
        if (NT_SUCCESS(status)) {
            /* Both storage allocations preceded the one-sector bitmap
             * reservation. Installing this mapping needs no late realloc;
             * never lose a reserved block in an unchecked merge failure. */
            RtlCopyMemory(newMap, dloc->DataLoc.Mapping,
                          mapBytes - sizeof(EXTENT_MAP));
            newMap[mapBytes / sizeof(EXTENT_MAP) - 1] = extra.Mapping[0];
            RtlZeroMemory((int8*)newMap + mapBytes, sizeof(EXTENT_MAP));
            MyFreePool__(dloc->DataLoc.Mapping);
            dloc->DataLoc.Mapping = newMap;
            newMap = NULL;
            dloc->DataLoc.Length = Offset + Length;
            UDFSetFileSize(Directory, dloc->DataLoc.Length);
        } else if (extra.Mapping) {
            UDFMarkSpaceAsXXX(Vcb, 0, extra.Mapping, AS_DISCARDED);
        }
        if (extra.Mapping)
            MyFreePool__(extra.Mapping);
        if (newMap)
            MyFreePool__(newMap);
    }
    ownsRange = dloc->DataLoc.Length >= 0 &&
        (uint64)Offset + Length <= (uint64)dloc->DataLoc.Length &&
        UDFDirectoryAppendAllocated(Vcb, dloc, Offset, Length);
    if (NT_SUCCESS(status) && !ownsRange)
        status = STATUS_FILE_CORRUPT_ERROR;
    if (ownsRange) {
        lba = UDFExtentOffsetToLba(Vcb, dloc->DataLoc.Mapping, Offset,
                                  NULL, NULL, NULL, NULL);
    }
    UDFAcquireResourceExclusive(&cache->Resource, TRUE);
    ASSERT(!cache->Length);
    if (ownsRange) {
        /* The placeholder for an unmapped start never reaches disk. */
        UDFSetUpTag(Vcb, (tag*)cache->Buffer, (uint16)Length,
                    UDFPhysLbaToPart(Vcb, part, lba), 0);
        cache->Offset = Offset;
        cache->Length = (ULONG)Length;
        cache->InlineOwned = TRUE;
        dloc->DataLoc.Modified = TRUE;
        dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
        *Handled = TRUE;
    } else {
        UDFReturnDirectoryAppendBuffer(Vcb, cache);
    }
    UDFReleaseResource(&cache->Resource);
    if (!NT_SUCCESS(status))
        UDFRememberMetadataWritebackError(IrpContext, Vcb, Directory, status);
    *WrittenBytes = NT_SUCCESS(status) ? Length : 0;
    return status;
}

/* A reserved name must be a complete deleted FID with no ICB reference.
 * It uses the same bounded owner, mapping/EOF checks and drain-before-FE
 * barrier as an ordinary append. It never publishes the new file itself.
 */
NTSTATUS
UDFReserveDirectoryFid(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO Directory, int64 Offset, SIZE_T Length,
    int8* Buffer, PSIZE_T WrittenBytes, PBOOLEAN Handled)
{
    PFILE_IDENT_DESC fid = (PFILE_IDENT_DESC)Buffer;
    LONG_AD empty;
    *WrittenBytes = 0;
    *Handled = FALSE;
    if (!UDFMayDeferNewCreate(IrpContext, Vcb) || !Directory ||
        !Directory->Dloc || !Directory->Dloc->DirIndex ||
        !Directory->Fcb || Directory->Dloc->CommonFcb != Directory->Fcb ||
        Directory->Fcb->FileInfo != Directory || Directory->Fcb->FcbReference <= 0 ||
        !FlagOn(Directory->Fcb->FcbState, FCB_STATE_IN_FCB_TABLE) ||
        !FlagOn(Directory->Fcb->FcbState, UDF_FCB_DIRECTORY | UDF_FCB_ROOT_DIRECTORY) ||
        FlagOn(Directory->Fcb->FcbState, UDF_FCB_DELETED | UDF_FCB_DELETE_ON_CLOSE) ||
        FlagOn(Vcb->VcbState, VCB_STATE_REMOVABLE_MEDIA) || !Buffer ||
        Length < sizeof(FILE_IDENT_DESC) || Length > Vcb->SectorSize ||
        fid->descTag.tagIdent != TID_FILE_IDENT_DESC ||
        fid->fileCharacteristics != FILE_DELETED)
        return STATUS_SUCCESS;
    RtlZeroMemory(&empty, sizeof(empty));
    if (RtlCompareMemory(&fid->icb, &empty, sizeof(empty)) != sizeof(empty))
        return STATUS_SUCCESS;
    if (Directory->Dloc->DataLoc.Offset) {
        PUDF_DATALOC_INFO dloc = Directory->Dloc;
        UDF_DIR_APPEND_CACHE* cache;
        NTSTATUS status;
        if (!dloc->FileEntry || !UDFCanStageFileEntry(Vcb, Directory) ||
            dloc->DataLoc.Offset != dloc->FileEntryLen ||
            (((icbtag*)(dloc->FileEntry + 1))->flags & ICB_FLAG_ALLOC_MASK) != ICB_FLAG_AD_IN_ICB ||
            dloc->DataLoc.Length < 0 || Offset != dloc->DataLoc.Length ||
            (uint64)dloc->DataLoc.Offset + (uint64)dloc->DataLoc.Length > Vcb->SectorSize ||
            !(cache = dloc->DirectoryAppend ? dloc->DirectoryAppend :
                                            UDFAllocateDirectoryAppend(Vcb, dloc)))
            return STATUS_SUCCESS;
        status = UDFOpenIntegrityForWrite(IrpContext, Vcb, FALSE);
        if (!NT_SUCCESS(status))
            return status;
        if (Length <= Vcb->SectorSize - dloc->DataLoc.Offset - (SIZE_T)Offset) {
            UDFAcquireResourceExclusive(&cache->Resource, TRUE);
            ASSERT(!cache->Length);
            if (cache->Length) {
                UDFReleaseResource(&cache->Resource);
                return STATUS_FILE_CORRUPT_ERROR;
            }
            RtlCopyMemory((int8*)dloc->FileEntry + dloc->DataLoc.Offset + (SIZE_T)Offset,
                          Buffer, Length);
            dloc->DataLoc.Length = Offset + Length;
            UDFSetFileSize(Directory, dloc->DataLoc.Length);
            dloc->DataLoc.Modified = TRUE;
            dloc->FE_Flags |= UDF_FE_FLAG_FE_MODIFIED;
            cache->InlineOwned = TRUE;
            *WrittenBytes = Length;
            *Handled = TRUE;
            UDFReleaseResource(&cache->Resource);
            return STATUS_SUCCESS;
        }
        /* Keep the existing move's input durable, as it was before inline
         * deferral. In particular, a failed/partial copy to the new extent
         * must not make the old, still-committed in-ICB FE stale. Only after
         * that full FE succeeds may mapping/retag follow the existing path.
         * The current new FID is beyond the old length and is not published. */
        {
            uint32 part = UDFGetRefPartNumByPhysLba(Vcb,
                               dloc->FELoc.Mapping[0].extLocation);
            if (part >= Vcb->PartitionMaps)
                return STATUS_FILE_CORRUPT_ERROR;
            status = UDFFlushFE(IrpContext, Vcb, Directory, part);
            if (!NT_SUCCESS(status))
                return status;
        }
        status = UDFWriteFile__(IrpContext, Vcb, Directory, Offset, Length,
                                FALSE, Buffer, WrittenBytes);
        if (NT_SUCCESS(status) && *WrittenBytes != Length)
            status = STATUS_IO_DEVICE_ERROR;
        if (NT_SUCCESS(status)) {
            UDFAcquireResourceExclusive(&cache->Resource, TRUE);
            cache->InlineOwned = TRUE;
            UDFReleaseResource(&cache->Resource);
            *Handled = TRUE;
        }
        return status;
    }
    {
        NTSTATUS status = UDFTryDirectoryAppendInternal(IrpContext, Vcb,
            Directory, Offset, Length, FALSE, Buffer, WrittenBytes, Handled, TRUE);
        if (!NT_SUCCESS(status) || *Handled)
            return status;
        return UDFGrowReservedDirectoryFid(IrpContext, Vcb, Directory, Offset,
            Length, Buffer, WrittenBytes, Handled);
    }
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
    if (FileInfo->Dloc->DataLoc.Offset) {
        PUDF_DATALOC_INFO dloc = FileInfo->Dloc;
        /* The cache control owns the resident in-ICB generation even when
         * it has no external append buffer. This also feeds externalization. */
        if (!dloc->FileEntry || dloc->DataLoc.Offset != dloc->FileEntryLen ||
            dloc->DataLoc.Length < 0 || (uint64)end > (uint64)dloc->DataLoc.Length ||
            (uint64)dloc->FileEntryLen + (uint64)dloc->DataLoc.Length > Vcb->SectorSize ||
            (((icbtag*)(dloc->FileEntry + 1))->flags & ICB_FLAG_ALLOC_MASK) != ICB_FLAG_AD_IN_ICB) {
            status = STATUS_FILE_CORRUPT_ERROR;
        } else if (Length) {
            RtlCopyMemory(Buffer, (int8*)dloc->FileEntry + dloc->FileEntryLen + (SIZE_T)Offset,
                          Length);
        }
        UDFReleaseResource(&cache->Resource);
        return status;
    }
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
    if (cache->Length || cache->InlineOwned) {
        return FALSE;
    }
    UDFReturnDirectoryAppendBuffer(Vcb,cache);
    ExDeleteResourceLite(&cache->Resource);
    MyFreePool__(cache);
    Dloc->DirectoryAppend = NULL;
    InterlockedExchangeAdd(&Vcb->DirectoryAppendBytes,-(LONG)sizeof(*cache));
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    InterlockedDecrement(&Vcb->DirectoryAppendDiag[7]);
#endif
    return TRUE;
}
