/* Copyright 2026 KosBeg. SPDX-License-Identifier: GPL-2.0-or-later */
#include "../udffs.h"
#include "fe_batch.h"

/* Batch only adjacent independent FEs within one partition. In particular,
 * do not fill gaps with a stale read or combine an FE with its dependent FID.
 * All validation precedes the first write; short and overreported completion
 * retain the entire set for idempotent retry by the owning FCBs. */
NTSTATUS
UDFCommitFileEntryBatch(PUDF_FE_BATCH_WRITE Entries, uint32 Count,
    int8* TransferBuffer, uint32* Order, PUDF_FE_BATCH_IO Write, void* Context)
{
    uint32 i, j, index, first, sectors;
    NTSTATUS status;
    SIZE_T written, requested;

    if (Count > UDF_FE_BATCH_CAPACITY ||
        (Count && (!Entries || !TransferBuffer || !Order || !Write)))
        return STATUS_INVALID_PARAMETER;
    if (!Count)
        return STATUS_SUCCESS;

    for (i = 0; i < Count; i++) {
        if (!Entries[i].Bytes)
            return STATUS_INVALID_PARAMETER;
        index = i;
        j = i;
        while (j &&
            (Entries[Order[j-1]].Partition > Entries[index].Partition ||
             (Entries[Order[j-1]].Partition == Entries[index].Partition &&
              Entries[Order[j-1]].Lba > Entries[index].Lba))) {
            Order[j] = Order[j-1];
            j--;
        }
        Order[j] = index;
    }
    for (i = 1; i < Count; i++) {
        if (Entries[Order[i-1]].Partition == Entries[Order[i]].Partition &&
            Entries[Order[i-1]].Lba == Entries[Order[i]].Lba)
            return STATUS_INVALID_PARAMETER;
    }

    for (first = 0; first < Count; first += sectors) {
        index = Order[first];
        sectors = 1;
        while (first + sectors < Count &&
               Entries[Order[first + sectors]].Partition == Entries[index].Partition &&
               Entries[index].Lba <= ((uint32)-1) - sectors &&
               Entries[Order[first + sectors]].Lba == Entries[index].Lba + sectors)
            sectors++;
        for (i = 0; i < sectors; i++)
            RtlCopyMemory(TransferBuffer + i * UDF_FE_BATCH_SECTOR,
                Entries[Order[first+i]].Bytes, UDF_FE_BATCH_SECTOR);
        written = 0;
        requested = sectors * UDF_FE_BATCH_SECTOR;
        status = Write(Context, Entries[index].Partition, Entries[index].Lba,
                       sectors, TransferBuffer, &written);
        if (!NT_SUCCESS(status))
            return status;
        if (written != requested)
            return STATUS_IO_DEVICE_ERROR;
    }
    return STATUS_SUCCESS;
}
