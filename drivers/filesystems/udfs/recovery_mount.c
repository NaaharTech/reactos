#include "udffs.h"
#include "udf_info/recovery_core.h"

typedef struct _UDFS_RECOVERY_MOUNT_IO {
    PDEVICE_OBJECT Target;
} UDFS_RECOVERY_MOUNT_IO;

static int
UdfsRecoverySectorIo(void *context, uint32_t lba, void *buffer,
                     BOOLEAN write)
{
    UDFS_RECOVERY_MOUNT_IO *io = (UDFS_RECOVERY_MOUNT_IO *)context;
    LARGE_INTEGER offset;
    IO_STATUS_BLOCK iosb;
    KEVENT event;
    PIRP irp;
    PIO_STACK_LOCATION stack;
    NTSTATUS status;

    offset.QuadPart = ((LONGLONG)lba) * UDFS_RECOVERY_SECTOR_SIZE;
    iosb.Status = STATUS_UNSUCCESSFUL;
    iosb.Information = 0;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(write ? IRP_MJ_WRITE : IRP_MJ_READ,
                                       io->Target, buffer,
                                       UDFS_RECOVERY_SECTOR_SIZE,
                                       &offset, &event, &iosb);
    if (!irp) return -1;
    stack = IoGetNextIrpStackLocation(irp);
    SetFlag(stack->Flags, SL_OVERRIDE_VERIFY_VOLUME);
    if (write) SetFlag(stack->Flags, SL_WRITE_THROUGH);
    status = IoCallDriver(io->Target, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    } else if (NT_SUCCESS(status)) {
        status = iosb.Status;
    }
    return NT_SUCCESS(status) &&
           iosb.Information == UDFS_RECOVERY_SECTOR_SIZE ? 0 : -1;
}

static int
UdfsRecoveryMountReadSector(void *context, uint32_t lba,
                       uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE])
{
    return UdfsRecoverySectorIo(context, lba, sector, FALSE);
}

static int
UdfsRecoveryMountWriteSector(void *context, uint32_t lba,
                        const uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE])
{
    return UdfsRecoverySectorIo(context, lba, (PVOID)sector, TRUE);
}

static int
UdfsRecoveryMountFlush(void *context)
{
    UDFS_RECOVERY_MOUNT_IO *io = (UDFS_RECOVERY_MOUNT_IO *)context;
    IO_STATUS_BLOCK iosb;
    KEVENT event;
    PIRP irp;
    NTSTATUS status;

    iosb.Status = STATUS_UNSUCCESSFUL;
    iosb.Information = 0;
    KeInitializeEvent(&event, NotificationEvent, FALSE);
    irp = IoBuildSynchronousFsdRequest(IRP_MJ_FLUSH_BUFFERS, io->Target,
                                       NULL, 0, NULL, &event, &iosb);
    if (!irp) return -1;
    status = IoCallDriver(io->Target, irp);
    if (status == STATUS_PENDING) {
        KeWaitForSingleObject(&event, Executive, KernelMode, FALSE, NULL);
        status = iosb.Status;
    } else if (NT_SUCCESS(status)) {
        status = iosb.Status;
    }
    /* A lower device that declines FLUSH cannot establish the required
     * bitmap-before-LVID persistence order. */
    return NT_SUCCESS(status) ? 0 : -1;
}

static void *
UdfsRecoveryMountAllocate(void *context, size_t bytes)
{
    UNREFERENCED_PARAMETER(context);
    if (!bytes || bytes > 16 * 1024 * 1024)
        return NULL;
    return ExAllocatePoolWithTag(NonPagedPool, bytes, 'RduU');
}

static void
UdfsRecoveryMountFree(void *context, void *buffer)
{
    UNREFERENCED_PARAMETER(context);
    ExFreePoolWithTag(buffer, 'RduU');
}

NTSTATUS
UDFRecoverDirtyVolumeBeforeLoad(PIRP_CONTEXT IrpContext, PVCB Vcb)
{
    UDFS_RECOVERY_MOUNT_IO io;
    UDFS_RECOVERY_READER reader;
    UDFS_RECOVERY_PROBE before, after;
    UDFS_RECOVERY_REPAIR_PLAN *plan;
    UDFS_RECOVERY_PROBE_STATUS status;
    uint8_t integrityType;
    UDF_TIME_STAMP timestamp;
    LONGLONG now;

    UNREFERENCED_PARAMETER(IrpContext);
    if (Vcb->SectorSize != UDFS_RECOVERY_SECTOR_SIZE ||
        Vcb->SessionStartLba != 0 ||
        Vcb->SessionEndLba == UINT32_MAX ||
        Vcb->TargetDeviceObject->DeviceType != FILE_DEVICE_DISK)
        return STATUS_SUCCESS;

    RtlZeroMemory(&reader, sizeof(reader));
    io.Target = Vcb->TargetDeviceObject;
    reader.Context = &io;
    reader.ReadSector = UdfsRecoveryMountReadSector;
    reader.WriteSector = UdfsRecoveryMountWriteSector;
    reader.Flush = UdfsRecoveryMountFlush;
    reader.Allocate = UdfsRecoveryMountAllocate;
    reader.Free = UdfsRecoveryMountFree;
    reader.SectorCount = Vcb->SessionEndLba + 1;
    status = UdfsRecoveryPeekIntegrity(&reader, &integrityType);
    if (status != UdfsRecoveryProbeValidLayout || integrityType != 0)
        return STATUS_SUCCESS;
    /* A dirty write-protected device remains available through the existing
     * read-only policy. Do not turn an optional repair into a mount failure. */
    if (UDFPerformDevIoCtrl(IOCTL_DISK_IS_WRITABLE, io.Target,
                            NULL, 0, NULL, 0, TRUE, NULL) ==
        STATUS_MEDIA_WRITE_PROTECTED)
        return STATUS_SUCCESS;
    status = UdfsRecoveryProbeLayout(&reader, &before);
    /* The probe has not written anything yet. Incomplete validation keeps
     * the pre-existing dirty/read-only mount policy. */
    if (status == UdfsRecoveryProbeNoMemory ||
        status == UdfsRecoveryProbeIoError)
        return STATUS_SUCCESS;
    if (status == UdfsRecoveryProbeValidLayout &&
        before.LvidIntegrityType == 1)
        return STATUS_SUCCESS;
    if (before.PrevailingLvidLba == 0 ||
        before.LvidIntegrityType != 0 ||
        (status != UdfsRecoveryProbeValidLayout &&
         status != UdfsRecoveryProbeGraphMismatch &&
         status != UdfsRecoveryProbeLvidMismatch)) {
        UDFPrint(("UDFS recovery: unsupported/corrupt state %u, existing mount policy\n",
                  (ULONG)status));
        return STATUS_SUCCESS;
    }

    plan = (UDFS_RECOVERY_REPAIR_PLAN *)
           UdfsRecoveryMountAllocate(&io, sizeof(*plan));
    if (!plan) return STATUS_INSUFFICIENT_RESOURCES;
    KeQuerySystemTime((PLARGE_INTEGER)&now);
    RtlZeroMemory(&timestamp, sizeof(timestamp));
    UDFTimeToUDF(now, &timestamp);
    status = UdfsRecoveryPrepareRepair(&reader, &before,
                                        (const uint8_t *)&timestamp, plan);
    if (status == UdfsRecoveryProbeUnsupported) {
        UDFPrint(("UDFS recovery: ownership class not repairable; read-only policy\n"));
        UdfsRecoveryMountFree(&io, plan);
        return STATUS_SUCCESS;
    }
    if (status != UdfsRecoveryProbeValidLayout) {
        UDFPrint(("UDFS recovery: no complete plan %u; read-only policy\n",
                  (ULONG)status));
        UdfsRecoveryMountFree(&io, plan);
        return STATUS_SUCCESS;
    }
    UDFPrint(("UDFS recovery: %lu referenced-free blocks, %lu bitmap sectors\n",
              (ULONG)before.ReferencedFreeMetadataBlocks,
              (ULONG)plan->BitmapEditCount));
    status = UdfsRecoveryApplyRepair(&reader, plan, &after);
    UdfsRecoveryMountFree(&io, plan);
    if (status != UdfsRecoveryProbeValidLayout) {
        UDFPrint(("UDFS recovery: apply/reprobe failed %u\n", (ULONG)status));
        return status == UdfsRecoveryProbeNoMemory ?
               STATUS_INSUFFICIENT_RESOURCES : STATUS_IO_DEVICE_ERROR;
    }
    UDFPrint(("UDFS recovery: checked bitmap/LVID commit complete\n"));
    return STATUS_SUCCESS;
}
