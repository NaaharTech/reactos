////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*************************************************************************
*
* File: Shutdown.cpp
*
* Module: UDF File System Driver (Kernel mode execution only)
*
* Description:
*   Contains code to handle the "shutdown notification" dispatch entry point.
*
*************************************************************************/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID                UDF_FILE_SHUTDOWN

/*************************************************************************
*
* Function: UDFCommonShutdown()
*
* Description:
*   The actual work is performed here. Basically, all we do here is
*   internally invoke a flush on all mounted logical volumes. This, in
*   tuen, will result in all open file streams being flushed to disk.
*
* Expected Interrupt Level (for execution) :
*
*  IRQL_PASSIVE_LEVEL
*
* Return Value: The first filesystem or lower-device shutdown failure.
*
*************************************************************************/
NTSTATUS
UDFCommonShutdown(
    _Inout_ PIRP_CONTEXT IrpContext,
    _Inout_ PIRP Irp
    )
{
    KEVENT Event;
    PVCB Vcb;
    PLIST_ENTRY Link;
    BOOLEAN VcbPresent = TRUE;
    NTSTATUS Status = STATUS_SUCCESS;
    NTSTATUS VolumeStatus;

    PAGED_CODE();

    // Make sure we don't get any pop-ups.

    SetFlag(IrpContext->Flags, IRP_CONTEXT_FLAG_DISABLE_POPUPS);

    // Initialize an event for doing calls down to
    // our target device objects.

    KeInitializeEvent(&Event, NotificationEvent, FALSE);

    // Indicate that shutdown has started.

    SetFlag(UdfData.Flags, UDF_DATA_FLAGS_SHUTDOWN);

    // Get everyone else out of the way

    UDFAcquireUdfData(IrpContext);

    _SEH2_TRY {

        // (a) Block all new "mount volume" requests by acquiring an appropriate
        //       global resource/lock.
        // (b) Go through your linked list of mounted logical volumes and for
        //       each such volume, do the following:
        //       (i) acquire the volume resource exclusively
        //       (ii) invoke UDFFlushLogicalVolume() (internally) to flush the
        //              open data streams belonging to the volume from the system
        //              cache
        //       (iii) Invoke the physical/virtual/logical target device object
        //              on which the volume is mounted and inform this device
        //              about the shutdown request (Use IoBuildSynchronouFsdRequest()
        //              to create an IRP with MajorFunction = IRP_MJ_SHUTDOWN that you
        //              will then issue to the target device object).
        //       (iv) Wait for the completion of the shutdown processing by the target
        //              device object
        //       (v) Release the VCB resource we will have acquired in (i) above.

        //  Now walk through all the mounted Vcb's and shutdown the target
        //  device objects.

        Link = UdfData.VcbQueue.Flink;

        while (Link != &(UdfData.VcbQueue)) {

            Vcb = CONTAINING_RECORD(Link, struct VCB, VcbLinks);

            // Move to the next link now since the current Vcb may be deleted.

            Link = Link->Flink;

            // If we have already been called before for this volume
            // (and yes this does happen), skip this volume as no writes
            // have been allowed since the first shutdown.

            if (FlagOn(Vcb->VcbState, VCB_STATE_SHUTDOWN) ||
                (Vcb->VcbCondition != VcbMounted)) {

                continue;
            }

            UDFAcquireVcbExclusive(IrpContext, Vcb, FALSE);

            {
            _SEH2_TRY {

                /* Keep the cached file state until its metadata has reached
                 * the volume.  The lock-volume path uses this same order. */
                VolumeStatus = UDFFlushVolume(IrpContext, Vcb, 0);
                if (NT_SUCCESS(VolumeStatus))
                    VolumeStatus = UDFPurgeVolume(IrpContext, Vcb);

            } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {

                VolumeStatus = _SEH2_GetExceptionCode();
                IrpContext->ExceptionStatus = STATUS_SUCCESS;
                UDFPrint(("UDF: shutdown flush exception %08lx\n", VolumeStatus));

            } _SEH2_END;
            }

            if (NT_SUCCESS(Status) && !NT_SUCCESS(VolumeStatus))
                Status = VolumeStatus;

            {
            _SEH2_TRY {

                IO_STATUS_BLOCK Iosb;
                NTSTATUS LowerStatus;
                PIRP NewIrp;

                Iosb.Status = STATUS_UNSUCCESSFUL;
                Iosb.Information = 0;
                NewIrp = IoBuildSynchronousFsdRequest(IRP_MJ_SHUTDOWN,
                                                      Vcb->TargetDeviceObject,
                                                      NULL,
                                                      0,
                                                      NULL,
                                                      &Event,
                                                      &Iosb);

                if (NewIrp == NULL) {
                    LowerStatus = STATUS_INSUFFICIENT_RESOURCES;
                } else {
                    KeClearEvent(&Event);
                    LowerStatus = IoCallDriver(Vcb->TargetDeviceObject, NewIrp);
                    if (LowerStatus == STATUS_PENDING) {
                        (VOID)KeWaitForSingleObject(&Event, Executive,
                                                    KernelMode, FALSE, NULL);
                        LowerStatus = Iosb.Status;
                    } else if (NT_SUCCESS(LowerStatus)) {
                        LowerStatus = Iosb.Status;
                    }
                }

                if (NT_SUCCESS(Status) && !NT_SUCCESS(LowerStatus))
                    Status = LowerStatus;

            } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {

                if (NT_SUCCESS(Status))
                    Status = _SEH2_GetExceptionCode();
                IrpContext->ExceptionStatus = STATUS_SUCCESS;
            } _SEH2_END;
            }

            SetFlag(Vcb->VcbState, VCB_STATE_SHUTDOWN);

            // Attempt to punch the volume down.

            VcbPresent = UDFCheckForDismount(IrpContext, Vcb, FALSE);

            if (VcbPresent) {

                UDFReleaseVcb(IrpContext, Vcb);
            }
        }

    } _SEH2_FINALLY {

        UDFReleaseUdfData(IrpContext);

        // Now, delete any device objects, etc. we may have created
        IoUnregisterFileSystem(UdfData.UDFDeviceObject_CD);
        if (UdfData.UDFDeviceObject_CD) {
            IoDeleteDevice(UdfData.UDFDeviceObject_CD);
            UdfData.UDFDeviceObject_CD = NULL;
        }
        IoUnregisterFileSystem(UdfData.UDFDeviceObject_HDD);
        if (UdfData.UDFDeviceObject_HDD) {
            IoDeleteDevice(UdfData.UDFDeviceObject_HDD);
            UdfData.UDFDeviceObject_HDD = NULL;
        }

        UDFCompleteRequest(IrpContext, Irp, Status);

    } _SEH2_END; // end of "__finally" processing

    return Status;
} // end UDFCommonShutdown()
