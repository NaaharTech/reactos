/* Copyright 2026 KosBeg. SPDX-License-Identifier: GPL-2.0-or-later
 * Bounded writeback of new, unpublished ordinary-file generations.
 */
#include "udffs.h"
#include "udf_info/fe_batch.h"

static BOOLEAN
UDFNewMetadataVolume(PVCB Vcb)
{
    return Vcb->VcbCondition == VcbMounted && !Vcb->CDR_Mode &&
        Vcb->SectorSize == 512 &&
        (Vcb->UdfRevision == 0x201 || Vcb->UdfRevision == 0x250) &&
        Vcb->TargetDeviceObject->DeviceType == FILE_DEVICE_DISK &&
        !FlagOn(Vcb->VcbState, VCB_STATE_VOLUME_READ_ONLY | UDF_VCB_FLAGS_DEAD);
}

/* FELoc.Length is the logical FE header, not its rounded allocation size.
 * The serializer separately proves the complete transfer is one sector. */
BOOLEAN
UDFCanStageFileEntry(PVCB Vcb, PUDF_FILE_INFO FileInfo)
{
    PUDF_DATALOC_INFO dloc = FileInfo->Dloc;
    return !Vcb->CDR_Mode && Vcb->SectorSize == 512 &&
        dloc->FELoc.Mapping && dloc->FELoc.Offset == 0 &&
        dloc->FELoc.Length > 0 && dloc->FELoc.Length <= 512 &&
        UDFGetExtentLength(dloc->FELoc.Mapping) == 512 &&
        !(dloc->FELoc.Mapping[0].extLength & ~UDF_EXTENT_LENGTH_MASK);
}

BOOLEAN
UDFMayDeferNewCreate(PIRP_CONTEXT IrpContext, PVCB Vcb)
{
    PIO_STACK_LOCATION irpSp;
    ULONG options;
    if (!UDFNewMetadataVolume(Vcb) || !IrpContext || !IrpContext->Irp ||
        IrpContext->MajorFunction != IRP_MJ_CREATE)
        return FALSE;
    irpSp = IoGetCurrentIrpStackLocation(IrpContext->Irp);
    options = irpSp->Parameters.Create.Options;
    return FlagOn(options, FILE_NON_DIRECTORY_FILE) &&
        !FlagOn(options, FILE_DIRECTORY_FILE | FILE_WRITE_THROUGH | FILE_NO_INTERMEDIATE_BUFFERING |
                         FILE_DELETE_ON_CLOSE | FILE_OPEN_BY_FILE_ID);
}

BOOLEAN
UDFNewFileCacheable(PVCB Vcb, PUDF_FILE_INFO FileInfo)
{
    PFCB fcb, parent;
    PLCB lcb;
    if (!UDFNewMetadataVolume(Vcb) || !FileInfo || !FileInfo->Dloc ||
        !FlagOn(FileInfo->Dloc->FE_Flags, UDF_FE_FLAG_NEW_UNPUBLISHED) ||
        !FileInfo->Dloc->FileEntry || !FileInfo->Dloc->FELoc.Mapping ||
        !(fcb = FileInfo->Fcb) || fcb->FileInfo != FileInfo ||
        FileInfo->Dloc->CommonFcb != fcb || fcb->FcbReference <= 0 ||
        !FlagOn(fcb->FcbState, FCB_STATE_IN_FCB_TABLE) ||
        FlagOn(fcb->FcbState, UDF_FCB_DIRECTORY | UDF_FCB_DELETE_ON_CLOSE | UDF_FCB_DELETED) ||
        UDFIsADirectory(FileInfo) || UDFIsAStream(FileInfo) ||
        UDFIsAStreamDir(FileInfo) || UDFHasAStreamDir(FileInfo) ||
        UDFGetFileNameLinkCount(FileInfo) != 1 ||
        (FileInfo->NextLinkedFile && FileInfo->NextLinkedFile != FileInfo) ||
        (FileInfo->PrevLinkedFile && FileInfo->PrevLinkedFile != FileInfo))
        return FALSE;
    if (!FileInfo->ParentFile || !(parent = FileInfo->ParentFile->Fcb) ||
        parent->FcbReference <= 0 || parent->FileInfo != FileInfo->ParentFile ||
        fcb->ParentFcb != parent || IsListEmpty(&fcb->ParentLcbQueue) ||
        fcb->ParentLcbQueue.Flink->Flink != &fcb->ParentLcbQueue)
        return FALSE;
    lcb = CONTAINING_RECORD(fcb->ParentLcbQueue.Flink, struct LCB, ChildFcbLinks);
    return lcb->ParentFcb == parent && lcb->ChildFcb == fcb;
}

BOOLEAN
UDFDeferNewFileMetadata(PIRP_CONTEXT IrpContext, PVCB Vcb, PUDF_FILE_INFO FileInfo)
{
    PIO_STACK_LOCATION irpSp;
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    if (IrpContext && IrpContext->MajorFunction == IRP_MJ_CLEANUP) {
        UDF_METADATA_COUNT(Vcb,19);
        if (FileInfo && FileInfo->Dloc && (FileInfo->Dloc->FE_Flags & UDF_FE_FLAG_NEW_UNPUBLISHED))
            UDF_METADATA_COUNT(Vcb,20);
        if (UDFNewFileCacheable(Vcb, FileInfo)) UDF_METADATA_COUNT(Vcb,21);
    }
#endif
    if (!UDFNewFileCacheable(Vcb, FileInfo) || !IrpContext || !IrpContext->Irp ||
        FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_WRITE_THROUGH))
        return FALSE;
    irpSp = IoGetCurrentIrpStackLocation(IrpContext->Irp);
    if (!irpSp->FileObject || FlagOn(irpSp->FileObject->Flags,
                                   FO_WRITE_THROUGH | FO_NO_INTERMEDIATE_BUFFERING))
        return FALSE;
    if (IrpContext->MajorFunction == IRP_MJ_CLEANUP) {
        BOOLEAN result = FlagOn(irpSp->FileObject->Flags, FO_CACHE_SUPPORTED) != 0;
        if (result) UDF_METADATA_COUNT(Vcb,22);
        else UDF_METADATA_COUNT(Vcb,25);
        return result;
    }
    if (IrpContext->MajorFunction == IRP_MJ_WRITE) {
        /* A zero-byte allocation update changes no payload. For real data
         * accept only the cached paging path, with a resident authoritative
         * in-ICB buffer; WT stack requests always reach the lower device. */
        return !FlagOn(irpSp->Flags, SL_WRITE_THROUGH) &&
            !(FlagOn(IrpContext->Irp->Flags, IRP_NOCACHE) &&
              !FlagOn(IrpContext->Irp->Flags, IRP_PAGING_IO));
    }
    return FALSE;
}

NTSTATUS
UDFReadNewFileData(PVCB Vcb, PUDF_FILE_INFO FileInfo,
    int64 Offset, SIZE_T Length, int8* Buffer, PBOOLEAN Handled)
{
    PUDF_DATALOC_INFO dloc = FileInfo->Dloc;
    *Handled = FALSE;
    if (!FlagOn(dloc->FE_Flags, UDF_FE_FLAG_NEW_UNPUBLISHED) ||
        (((PFILE_ENTRY)dloc->FileEntry)->icbTag.flags & ICB_FLAG_ALLOC_MASK) != ICB_FLAG_AD_IN_ICB ||
        dloc->DataLoc.Offset != dloc->FileEntryLen)
        return STATUS_SUCCESS;
    *Handled = TRUE;
    if (Offset < 0 || (uint64)Offset > (uint64)dloc->DataLoc.Length ||
        Length > (uint64)dloc->DataLoc.Length - (uint64)Offset ||
        (uint64)dloc->FileEntryLen + (uint64)dloc->DataLoc.Length > Vcb->SectorSize)
        return STATUS_FILE_CORRUPT_ERROR;
    if (Length)
        RtlCopyMemory(Buffer, (int8*)dloc->FileEntry + dloc->FileEntryLen + (SIZE_T)Offset, Length);
    return STATUS_SUCCESS;
}

NTSTATUS
UDFTakeMetadataWritebackError(PVCB Vcb)
{
    return (NTSTATUS)InterlockedExchange(&Vcb->MetadataWritebackError, STATUS_SUCCESS);
}

VOID
UDFRememberMetadataWritebackError(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PUDF_FILE_INFO FileInfo, NTSTATUS Status)
{
    UNREFERENCED_PARAMETER(FileInfo);
    if (!NT_SUCCESS(Status) && IrpContext &&
        FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_WRITER))
        InterlockedCompareExchange(&Vcb->MetadataWritebackError, Status, STATUS_SUCCESS);
}

typedef struct _UDF_FE_OWNER {
    PFCB Fcb;
    PUDF_FILE_INFO FileInfo;
    PUDF_DATALOC_INFO Dloc;
    uint32 Lba;
    uint32 Partition;
    BOOLEAN Staged;
    BOOLEAN MainHeld;
    BOOLEAN PagingHeld;
    int8 Bytes[512];
} UDF_FE_OWNER;

/* Only pointer slots are snapshotted; the per-IO owner/buffer and resource
 * cohort stays bounded to64. Every slot owns one FCB reference, transferred
 * exactly once into a cohort or released by the outer unwind. */
#define UDF_FE_SNAPSHOT_BUDGET (4 * 1024 * 1024)
typedef struct _UDF_FE_VOLUME_SNAPSHOT {
    uint32 Count;
    uint32 Next;
    PFCB* Files;
} UDF_FE_VOLUME_SNAPSHOT;

typedef struct _UDF_FE_WRITEBACK {
    PIRP_CONTEXT IrpContext;
    PVCB Vcb;
    uint32 Count;
    uint32 StagedCount;
    UDF_FE_OWNER Owner[UDF_FE_BATCH_CAPACITY];
    UDF_FE_BATCH_WRITE Write[UDF_FE_BATCH_CAPACITY];
    uint32 Order[UDF_FE_BATCH_CAPACITY];
    int8 Transfer[UDF_FE_BATCH_CAPACITY * UDF_FE_BATCH_SECTOR];
} UDF_FE_WRITEBACK;

static NTSTATUS
UDFBatchSectorWrite(void* Context, uint32 Partition, uint32 Lba,
    uint32 Sectors, int8* Buffer, PSIZE_T WrittenBytes)
{
    UDF_FE_WRITEBACK* batch = Context;
    if (Partition >= batch->Vcb->PartitionMaps)
        return STATUS_FILE_CORRUPT_ERROR;
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    InterlockedIncrement(&batch->Vcb->MetadataBatchDiag[2]);
    InterlockedExchangeAdd(&batch->Vcb->MetadataBatchDiag[3], Sectors);
#endif
    /* Same translated primary/mirror lower path as an aligned FE extent.
     * All FEs are independent; no FID is part of this transfer. */
    return UDFWriteSectors(batch->IrpContext, batch->Vcb, TRUE, Lba,
                          Sectors, FALSE, Buffer, WrittenBytes);
}

static BOOLEAN
UDFNewEntryDirty(PUDF_FILE_INFO FileInfo)
{
    PUDF_DATALOC_INFO d = FileInfo->Dloc;
    return (d->FE_Flags & UDF_FE_FLAG_FE_MODIFIED) || d->FELoc.Modified ||
        d->DataLoc.Modified || d->AllocLoc.Modified;
}

static VOID
UDFHoldBatchOwner(PIRP_CONTEXT IrpContext, PVCB Vcb,
    UDF_FE_WRITEBACK* Batch, PFCB Fcb)
{
    uint32 i;
    if (!Fcb || Batch->Count == UDF_FE_BATCH_CAPACITY || Fcb->FcbReference != 1 ||
        Fcb->FcbCleanup != 0 || !UDFNewFileCacheable(Vcb, Fcb->FileInfo) ||
        !UDFNewEntryDirty(Fcb->FileInfo))
        return;
    for (i = 0; i < Batch->Count; i++)
        if (Batch->Owner[i].Fcb == Fcb)
            return;
    /* Caller holds FcbTableMutex and VcbMutex, while VCB exclusive blocks
     * queued close workers and new namespace operations. */
    Fcb->FcbReference++;
    Batch->Owner[Batch->Count++].Fcb = Fcb;
    UNREFERENCED_PARAMETER(IrpContext);
}

static NTSTATUS
UDFReleaseMetadataOwner(PIRP_CONTEXT IrpContext, PVCB Vcb, PFCB Fcb)
{
    BOOLEAN removed = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    UDFAcquireFcbExclusive(IrpContext, Fcb, FALSE);
    UDFLockVcb(IrpContext, Vcb);
    ASSERT(Fcb->FcbReference > 0);
    Fcb->FcbReference--;
    UDFUnlockVcb(IrpContext, Vcb);
    if (!Fcb->FcbReference) {
        BOOLEAN writer = FlagOn(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_WRITER) != 0;
        /* Teardown is void, but its final FE/FID flush can fail. Route that
         * error through the writeback latch even in a user volume flush;
         * otherwise a later successful tree retry could hide the failure. */
        SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_WRITER);
        _SEH2_TRY {
            UDFTeardownStructures(IrpContext, Fcb, FALSE, &removed);
            status = writer ? (NTSTATUS)InterlockedCompareExchange(
                &Vcb->MetadataWritebackError,STATUS_SUCCESS,STATUS_SUCCESS) :
                UDFTakeMetadataWritebackError(Vcb);
        } _SEH2_FINALLY {
            if (!writer)
                ClearFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_METADATA_WRITER);
        } _SEH2_END;
    }
    if (!removed)
        UDFReleaseFcb(IrpContext, Fcb);
    return status;
}

static NTSTATUS
UDFWritebackNewFileBatchInternal(PIRP_CONTEXT IrpContext, PVCB Vcb,
    PFCB CurrentFcb, UDF_FE_VOLUME_SNAPSHOT* Snapshot, PBOOLEAN More)
{
    UDF_FE_WRITEBACK* batch;
    PVOID restart = NULL;
    PFCB fcb;
    uint32 i;
    NTSTATUS status = STATUS_SUCCESS;
    BOOLEAN tableHeld = FALSE, vcbHeld = FALSE;
    BOOLEAN volume = Snapshot != NULL;
    if (More) *More = FALSE;

#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
    UDF_METADATA_COUNT(Vcb,13);
    if (CurrentFcb) {
        if (CurrentFcb->FcbReference == 1) UDF_METADATA_COUNT(Vcb,14);
        if (!CurrentFcb->FcbCleanup) UDF_METADATA_COUNT(Vcb,15);
        if (CurrentFcb->FileInfo && CurrentFcb->FileInfo->Dloc &&
            (CurrentFcb->FileInfo->Dloc->FE_Flags & UDF_FE_FLAG_NEW_UNPUBLISHED))
            UDF_METADATA_COUNT(Vcb,16);
        if (UDFNewFileCacheable(Vcb,CurrentFcb->FileInfo)) UDF_METADATA_COUNT(Vcb,17);
    }
#endif
    ASSERT_EXCLUSIVE_VCB(Vcb);
    if (!UDFNewMetadataVolume(Vcb))
        return STATUS_SUCCESS;
    if (!volume && (!CurrentFcb || CurrentFcb->FcbReference != 1 ||
        CurrentFcb->FcbCleanup || !UDFNewFileCacheable(Vcb,CurrentFcb->FileInfo) ||
        !UDFNewEntryDirty(CurrentFcb->FileInfo)))
        return STATUS_SUCCESS;
    batch = MyAllocatePool__(NonPagedPool, sizeof(*batch));
    if (!batch) {
        if (volume) UDF_METADATA_COUNT(Vcb,46);
        return STATUS_SUCCESS; // Outer unwind drops pending pins; tree flush remains required.
    }
    RtlZeroMemory(batch, sizeof(*batch));
    batch->IrpContext = IrpContext;
    batch->Vcb = Vcb;

    _SEH2_TRY {
        if (volume) {
            /* The snapshot's references protect these objects independently
             * of later generic-table deletion or rebalancing. No cursor or
             * table-element pointer survives outside the capture lock. The
             * assignments below make no raising calls before ownership has
             * transferred into the cohort's ordinary finally block. */
            while (batch->Count < UDF_FE_BATCH_CAPACITY &&
                   Snapshot->Next < Snapshot->Count) {
                batch->Owner[batch->Count++].Fcb = Snapshot->Files[Snapshot->Next++];
            }
        } else {
            UDFLockFcbTable(IrpContext, Vcb);
            tableHeld = TRUE;
            UDFLockVcb(IrpContext, Vcb);
            vcbHeld = TRUE;
            UDFHoldBatchOwner(IrpContext, Vcb, batch, CurrentFcb);
            while (batch->Count < UDF_FE_BATCH_CAPACITY &&
                   (fcb = UDFGetNextFcb(IrpContext, Vcb, &restart))) {
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
                UDF_METADATA_COUNT(Vcb,7);
                if (InterlockedCompareExchange(&fcb->MetadataCloseQueued,0,0)) {
                    UDF_METADATA_COUNT(Vcb,8);
                    if (fcb->FcbReference == 1) UDF_METADATA_COUNT(Vcb,9);
                    if (!fcb->FcbCleanup) UDF_METADATA_COUNT(Vcb,10);
                    if (fcb->FileInfo && fcb->FileInfo->Dloc &&
                        (fcb->FileInfo->Dloc->FE_Flags & UDF_FE_FLAG_NEW_UNPUBLISHED))
                        UDF_METADATA_COUNT(Vcb,11);
                    if (UDFNewFileCacheable(Vcb,fcb->FileInfo)) UDF_METADATA_COUNT(Vcb,12);
                }
#endif
                if (InterlockedCompareExchange(&fcb->MetadataCloseQueued,0,0))
                    UDFHoldBatchOwner(IrpContext, Vcb, batch, fcb);
            }
            UDFUnlockVcb(IrpContext, Vcb);
            vcbHeld = FALSE;
            UDFUnlockFcbTable(IrpContext, Vcb);
            tableHeld = FALSE;
        }

#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
        InterlockedExchangeAdd(&Vcb->MetadataBatchDiag[5],batch->Count);
        if ((LONG)batch->Count > Vcb->MetadataBatchDiag[6])
            Vcb->MetadataBatchDiag[6] = batch->Count; // exclusive VCB
#endif
        if (volume) {
            if (More) *More = batch->Count != 0;
            /* VCB exclusive excludes user create/rename/truncate. Captured
             * ordinary FCBs are unique and in the table's signed FileId
             * order. Paging callbacks take one Main then its Paging resource;
             * directories, aliases and streams cannot enter this cohort.
             * Do not call Cc or last-reference teardown while it is held. */
            for (i = 0; i < batch->Count; i++) {
                UDF_FE_OWNER* owner = &batch->Owner[i];
                ASSERT(!i || batch->Owner[i-1].Fcb->FileId.QuadPart <
                              owner->Fcb->FileId.QuadPart);
                UDFAcquireFcbExclusive(IrpContext,owner->Fcb,FALSE);
                owner->MainHeld = TRUE;
                UDFAcquirePagingIoExclusive(IrpContext,owner->Fcb);
                owner->PagingHeld = TRUE;
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
                UDF_METADATA_COUNT(Vcb,41);
#endif
            }
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
            UDF_METADATA_COUNT(Vcb,39);
            InterlockedExchangeAdd(&Vcb->MetadataBatchDiag[40],batch->Count);
#endif
        }
        /* Close-queue cohorts have no surviving FILE_OBJECT operations and
         * retain their old one-Main-at-a-time path. Volume cohorts may still
         * have paging writers, so their resources span prepare -> IO -> ACK. */
        for (i = 0; i < batch->Count; i++) {
            UDF_FE_OWNER* owner = &batch->Owner[i];
            if (!volume)
                UDFAcquireFcbExclusive(IrpContext, owner->Fcb, FALSE);
            _SEH2_TRY {
                if (UDFNewFileCacheable(Vcb, owner->Fcb->FileInfo)) {
                    uint32 partition;
                    owner->FileInfo = owner->Fcb->FileInfo;
                    owner->Dloc = owner->FileInfo->Dloc;
                    partition = UDFGetRefPartNumByPhysLba(Vcb,
                        owner->Dloc->FELoc.Mapping[0].extLocation);
                    if (partition < Vcb->PartitionMaps) {
                        status = UDFStageNewFileEntry(IrpContext, Vcb,
                            owner->FileInfo, partition, owner->Bytes, &owner->Staged);
                        if (NT_SUCCESS(status) && owner->Staged) {
                            /* Serialization may relocate a known-bad FE.
                             * Bind the staged bytes to its final mapping,
                             * never the address seen before preparation. */
                            owner->Lba = owner->Dloc->FELoc.Mapping[0].extLocation;
                            owner->Partition = UDFGetRefPartNumByPhysLba(Vcb, owner->Lba);
                            if (owner->FileInfo->Dloc != owner->Dloc ||
                                owner->Partition != partition) {
                                status = STATUS_FILE_CORRUPT_ERROR;
                            } else {
                                UDF_FE_BATCH_WRITE* write = &batch->Write[batch->StagedCount++];
                                write->Lba = owner->Lba;
                                write->Partition = owner->Partition;
                                write->Bytes = owner->Bytes;
                            }
                        }
                    }
                }
            } _SEH2_FINALLY {
                if (!volume) {
                    UDFReleaseFcb(IrpContext, owner->Fcb);
                }
            } _SEH2_END;
            if (!NT_SUCCESS(status))
                break;
        }
        if (NT_SUCCESS(status))
            status = UDFCommitFileEntryBatch(batch->Write, batch->StagedCount,
                batch->Transfer, batch->Order, UDFBatchSectorWrite, batch);
        if (NT_SUCCESS(status)) {
            for (i = 0; i < batch->Count; i++) {
                UDF_FE_OWNER* owner = &batch->Owner[i];
                if (!owner->Staged)
                    continue;
                if (!volume)
                    UDFAcquireFcbExclusive(IrpContext, owner->Fcb, FALSE);
                _SEH2_TRY {
                    /* Do not acknowledge a changed identity/generation. A
                     * normal per-file flush will serialize it again before
                     * its valid FID is written. */
                    if (owner->Fcb->FileInfo == owner->FileInfo &&
                        owner->FileInfo->Dloc == owner->Dloc &&
                        owner->Dloc->FELoc.Mapping[0].extLocation == owner->Lba &&
                        !owner->Dloc->DataLoc.Modified && !owner->Dloc->AllocLoc.Modified &&
                        RtlCompareMemory(owner->Bytes, owner->Dloc->FileEntry, 512) == 512) {
                        owner->Dloc->FE_Flags &= ~UDF_FE_FLAG_FE_MODIFIED;
                        owner->Dloc->FELoc.Modified = FALSE;
                    }
                } _SEH2_FINALLY {
                    if (!volume) {
                        UDFReleaseFcb(IrpContext, owner->Fcb);
                    }
                } _SEH2_END;
            }
        }
    } _SEH2_FINALLY {
        if (vcbHeld) {
            UDFUnlockVcb(IrpContext, Vcb);
        }
        if (tableHeld) {
            UDFUnlockFcbTable(IrpContext, Vcb);
        }
        /* Drop every cohort resource before any per-owner last-reference
         * release can walk its parent directory or call the cache manager. */
        for (i = batch->Count; i; i--) {
            UDF_FE_OWNER* owner = &batch->Owner[i-1];
            if (owner->PagingHeld) {
                UDFReleasePagingIo(IrpContext,owner->Fcb);
                owner->PagingHeld = FALSE;
            }
            if (owner->MainHeld) {
                UDFReleaseFcb(IrpContext,owner->Fcb);
                owner->MainHeld = FALSE;
            }
        }
        if (_SEH2_AbnormalTermination())
            status = STATUS_UNSUCCESSFUL;
        UDFRememberMetadataWritebackError(IrpContext, Vcb, NULL, status);
#ifdef UDF_METADATA_BATCH_DIAGNOSTICS
        InterlockedIncrement(&Vcb->MetadataBatchDiag[0]);
        InterlockedExchangeAdd(&Vcb->MetadataBatchDiag[1], batch->StagedCount);
        if (!NT_SUCCESS(status))
            InterlockedIncrement(&Vcb->MetadataBatchDiag[4]);
#endif
        for (i = 0; i < batch->Count; i++) {
            NTSTATUS releaseStatus = UDFReleaseMetadataOwner(
                IrpContext, Vcb, batch->Owner[i].Fcb);
            if (NT_SUCCESS(status))
                status = releaseStatus;
        }
        MyFreePool__(batch);
    } _SEH2_END;
    return status;
}

NTSTATUS
UDFWritebackNewFileBatch(PIRP_CONTEXT IrpContext, PVCB Vcb, PFCB CurrentFcb)
{
    return UDFWritebackNewFileBatchInternal(IrpContext,Vcb,CurrentFcb,NULL,NULL);
}

NTSTATUS
UDFWritebackNewVolumeFiles(PIRP_CONTEXT IrpContext, PVCB Vcb)
{
    UDF_FE_VOLUME_SNAPSHOT snapshot;
    PVOID restart = NULL;
    PFCB fcb;
    uint32 capacity;
    BOOLEAN more, tableHeld = FALSE, vcbHeld = FALSE;
    NTSTATUS status = STATUS_SUCCESS;
    ASSERT_EXCLUSIVE_VCB(Vcb);
    UDF_METADATA_COUNT(Vcb,38);
    if (!UDFNewMetadataVolume(Vcb))
        return STATUS_SUCCESS;
    RtlZeroMemory(&snapshot, sizeof(snapshot));

    /* Size without the VCB fast mutex; pool allocation must not extend the
     * capture critical section. A concurrent table shrink is harmless. If
     * more entries appear, only this bounded prefix is optimized; the full
     * mandatory tree flush still visits every remaining dirty generation. */
    UDFLockFcbTable(IrpContext, Vcb);
    _SEH2_TRY {
        capacity = RtlNumberGenericTableElements(&Vcb->FcbTable);
    } _SEH2_FINALLY {
        UDFUnlockFcbTable(IrpContext, Vcb);
    } _SEH2_END;
    if (!capacity)
        return STATUS_SUCCESS;
    if (capacity > UDF_FE_SNAPSHOT_BUDGET / sizeof(PFCB)) {
        UDF_METADATA_COUNT(Vcb,45);
        return STATUS_SUCCESS;
    }
    snapshot.Files = MyAllocatePool__(NonPagedPool, capacity * sizeof(PFCB));
    if (!snapshot.Files) {
        UDF_METADATA_COUNT(Vcb,44);
        return STATUS_SUCCESS;
    }

    _SEH2_TRY {
        UDFLockFcbTable(IrpContext, Vcb);
        tableHeld = TRUE;
        UDFLockVcb(IrpContext, Vcb);
        vcbHeld = TRUE;
        while (snapshot.Count < capacity &&
               (fcb = UDFGetNextFcb(IrpContext, Vcb, &restart))) {
            UDF_METADATA_COUNT(Vcb,7);
            UDF_METADATA_COUNT(Vcb,43);
            if (!fcb->FcbNonpaged || fcb->Header.PagingIoResource !=
                    &fcb->FcbNonpaged->FcbPagingIoResource ||
                fcb->FcbReference != 1 || fcb->FcbCleanup != 0 ||
                !UDFNewFileCacheable(Vcb, fcb->FileInfo) ||
                !UDFNewEntryDirty(fcb->FileInfo))
                continue;
            /* This pin keeps the exact canonical FI/Dloc/LCB lifetime even
             * if the last FILE_OBJECT close consumes its earlier reference
             * before this owner's cohort is reached. */
            fcb->FcbReference++;
            snapshot.Files[snapshot.Count++] = fcb;
            UDF_METADATA_COUNT(Vcb,42);
        }
        UDFUnlockVcb(IrpContext, Vcb);
        vcbHeld = FALSE;
        UDFUnlockFcbTable(IrpContext, Vcb);
        tableHeld = FALSE;

        do {
            status = UDFWritebackNewFileBatchInternal(IrpContext,Vcb,NULL,&snapshot,&more);
        } while (NT_SUCCESS(status) && more && snapshot.Next < snapshot.Count);
    } _SEH2_FINALLY {
        if (vcbHeld) {
            UDFUnlockVcb(IrpContext, Vcb);
        }
        if (tableHeld) {
            UDFUnlockFcbTable(IrpContext, Vcb);
        }
        if (_SEH2_AbnormalTermination())
            status = STATUS_UNSUCCESSFUL;
        /* A failed stage/write or a cohort allocation failure cannot leak
         * all the not-yet-transferred snapshot owners. No cohort resources
         * are held while this can perform a last-reference teardown. */
        while (snapshot.Next < snapshot.Count) {
            UDF_METADATA_COUNT(Vcb,47);
            NTSTATUS releaseStatus = UDFReleaseMetadataOwner(
                IrpContext,Vcb,snapshot.Files[snapshot.Next++]);
            if (NT_SUCCESS(status))
                status = releaseStatus;
        }
        MyFreePool__(snapshot.Files);
    } _SEH2_END;
    /* This is only a metadata phase, not the explicit data/tree/device
     * barrier. The caller still runs the complete original volume flush. */
    return status;
}
