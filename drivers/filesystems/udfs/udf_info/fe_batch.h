/* Copyright 2026 KosBeg. SPDX-License-Identifier: GPL-2.0-or-later */
#ifndef _UDF_FE_BATCH_H_
#define _UDF_FE_BATCH_H_

#define UDF_FE_BATCH_CAPACITY 64
#define UDF_FE_BATCH_SECTOR   512

typedef struct _UDF_FE_BATCH_WRITE {
    uint32 Lba;
    uint32 Partition;
    int8* Bytes;
} UDF_FE_BATCH_WRITE, *PUDF_FE_BATCH_WRITE;

typedef NTSTATUS (*PUDF_FE_BATCH_IO)(
    void* Context, uint32 Partition, uint32 Lba, uint32 Sectors,
    int8* Buffer, PSIZE_T WrittenBytes);

/* The caller retains every generation until this whole operation succeeds.
 * No FID publication or dirty-state acknowledgement occurs in this helper. */
NTSTATUS
UDFCommitFileEntryBatch(
    PUDF_FE_BATCH_WRITE Entries, uint32 Count,
    int8* TransferBuffer, uint32* Order,
    PUDF_FE_BATCH_IO Write, void* Context);

#endif
