////////////////////////////////////////////////////////////////////
// Copyright (C) Alexander Telyatnikov, Ivan Keliukh, Yegor Anchishkin, SKIF Software, 1999-2013. Kiev, Ukraine
// All rights reserved
// This file was released under the GPLv2 on June 2015.
////////////////////////////////////////////////////////////////////
/*************************************************************************
*
* File: SecurSup.cpp
*
* Module: UDF File System Driver (Kernel mode execution only)
*
* Description:
*   Contains code to handle the "Get/Set Security" dispatch entry points.
*
*************************************************************************/

#include            "udffs.h"

// define the file specific bug-check id
#define         UDF_BUG_CHECK_ID                UDF_FILE_SECURITY

static NTSTATUS
UDFReadSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo,
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    );

static NTSTATUS
UDFBuildDefaultSecurityDescriptor(
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    );

static BOOLEAN
UDFIsRecycleBinRoot(
    PFILE_OBJECT FileObject,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo
    )
{
    UNICODE_STRING FileName;
    UNICODE_STRING RecycleBinName = RTL_CONSTANT_STRING(L"$RECYCLE.BIN");

    if (!FileObject || !Vcb || !Vcb->RootIndexFcb ||
        !FileInfo || !FileInfo->ParentFile ||
        FileInfo->ParentFile->Fcb != Vcb->RootIndexFcb)
        return FALSE;

    FileName = FileObject->FileName;
    while (FileName.Length >= sizeof(WCHAR) &&
           FileName.Buffer[0] == L'\\') {
        FileName.Buffer++;
        FileName.Length -= sizeof(WCHAR);
    }
    while (FileName.Length >= sizeof(WCHAR) &&
           FileName.Buffer[(FileName.Length / sizeof(WCHAR)) - 1] == L'\\')
        FileName.Length -= sizeof(WCHAR);

    return RtlEqualUnicodeString(&FileName, &RecycleBinName, TRUE);
}

static BOOLEAN
UDFIsRecycleBinDirectory(
    PUDF_FILE_INFO FileInfo,
    PVCB Vcb
    )
{
    NTSTATUS Status;
    UNICODE_STRING FileName;
    UNICODE_STRING RecycleBinName = RTL_CONSTANT_STRING(L"$RECYCLE.BIN");
    BOOLEAN IsRecycleBin;

    if (!FileInfo || !FileInfo->ParentFile ||
        !Vcb || !Vcb->RootIndexFcb ||
        FileInfo->ParentFile->Fcb != Vcb->RootIndexFcb)
        return FALSE;

    Status = UDFGetFileNameFromFileInfo(FileInfo, &FileName);
    if (!NT_SUCCESS(Status) || !FileName.Buffer)
        return FALSE;

    IsRecycleBin = RtlEqualUnicodeString(&FileName, &RecycleBinName, TRUE);
    MyFreePool__(FileName.Buffer);
    return IsRecycleBin;
}

static NTSTATUS
UDFSetRecycleBinUsersInheritance(
    PSECURITY_DESCRIPTOR SecurityDescriptor
    )
{
    NTSTATUS Status;
    PACL Dacl;
    BOOLEAN DaclPresent;
    ULONG i;

    Status = RtlGetDaclSecurityDescriptor(SecurityDescriptor, &DaclPresent,
                                          &Dacl, NULL);
    if (!NT_SUCCESS(Status) || !DaclPresent || !Dacl)
        return Status;

    for (i = 0; i < Dacl->AceCount; i++) {
        PACE_HEADER AceHeader;

        Status = RtlGetAce(Dacl, i, (PVOID *)&AceHeader);
        if (!NT_SUCCESS(Status))
            return Status;

        if (AceHeader->AceType == ACCESS_ALLOWED_ACE_TYPE &&
            AceHeader->AceSize >=
                FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                RtlLengthSid(SeExports->SeAliasUsersSid)) {
            PACCESS_ALLOWED_ACE Ace = (PACCESS_ALLOWED_ACE)AceHeader;

            if (RtlEqualSid((PSID)&Ace->SidStart,
                            SeExports->SeAliasUsersSid) ||
                RtlEqualSid((PSID)&Ace->SidStart,
                            SeExports->SeAuthenticatedUsersSid)) {
                AceHeader->AceFlags |= NO_PROPAGATE_INHERIT_ACE;
                AceHeader->AceFlags |= OBJECT_INHERIT_ACE |
                                       CONTAINER_INHERIT_ACE;
            }
        }
    }

    return STATUS_SUCCESS;
}

static NTSTATUS
UDFAddRecycleBinCreatorAce(
    PSECURITY_DESCRIPTOR *SecurityDescriptor,
    PACCESS_STATE AccessState
    )
{
    NTSTATUS Status;
    PTOKEN_USER UserInfo = NULL;
    PACL ExistingDacl = NULL;
    PACL Dacl;
    PSECURITY_DESCRIPTOR AbsoluteDescriptor = NULL;
    PSECURITY_DESCRIPTOR RelativeDescriptor = NULL;
    PSECURITY_DESCRIPTOR OriginalDescriptor;
    PSECURITY_DESCRIPTOR UpdatedDescriptor;
    BOOLEAN DaclPresent;
    BOOLEAN DaclDefaulted;
    BOOLEAN AcePresent = FALSE;
    ULONG ExistingAceLength = 0;
    ULONG AceLength;
    ULONG DaclLength;
    ULONG AbsoluteLength;
    ULONG RelativeLength = 0;
    ULONG i;
    SECURITY_INFORMATION SecurityInformation = DACL_SECURITY_INFORMATION;
    PACCESS_TOKEN Token;

    if (!AccessState)
        return STATUS_INVALID_PARAMETER;

    Token = SeQuerySubjectContextToken(&AccessState->SubjectSecurityContext);
    Status = SeQueryInformationToken(Token, TokenUser, (PVOID *)&UserInfo);
    if (!NT_SUCCESS(Status))
        return Status;

    Status = RtlGetDaclSecurityDescriptor(*SecurityDescriptor, &DaclPresent,
                                          &ExistingDacl, &DaclDefaulted);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    if (ExistingDacl) {
        for (i = 0; i < ExistingDacl->AceCount; i++) {
            PACE_HEADER ExistingAce;

            Status = RtlGetAce(ExistingDacl, i, (PVOID *)&ExistingAce);
            if (!NT_SUCCESS(Status))
                goto Cleanup;
            ExistingAceLength += ExistingAce->AceSize;

            if (ExistingAce->AceType == ACCESS_ALLOWED_ACE_TYPE &&
                ExistingAce->AceSize >=
                    FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                    RtlLengthSid(UserInfo->User.Sid)) {
                PACCESS_ALLOWED_ACE AccessAce =
                    (PACCESS_ALLOWED_ACE)ExistingAce;

                if (RtlEqualSid((PSID)&AccessAce->SidStart,
                                UserInfo->User.Sid) &&
                    AccessAce->Mask == FILE_ALL_ACCESS &&
                    ExistingAce->AceFlags ==
                        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE)) {
                    AcePresent = TRUE;
                }
            }
        }
    }
    if (AcePresent) {
        Status = STATUS_SUCCESS;
        goto Cleanup;
    }

    AceLength = FIELD_OFFSET(ACCESS_ALLOWED_ACE, SidStart) +
                RtlLengthSid(UserInfo->User.Sid);
    DaclLength = sizeof(ACL) + ExistingAceLength + AceLength;
    if (DaclLength > MAXUSHORT) {
        Status = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    AbsoluteLength = sizeof(SECURITY_DESCRIPTOR) + DaclLength;
    AbsoluteDescriptor = MyAllocatePool__(PagedPool, AbsoluteLength);
    if (!AbsoluteDescriptor) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Dacl = (PACL)((PUCHAR)AbsoluteDescriptor + sizeof(SECURITY_DESCRIPTOR));
    Status = RtlCreateSecurityDescriptor(AbsoluteDescriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Dacl, DaclLength,
                              ExistingDacl ? ExistingDacl->AclRevision :
                                             ACL_REVISION);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    if (ExistingDacl) {
        for (i = 0; i < ExistingDacl->AceCount; i++) {
            PACE_HEADER ExistingAce;

            Status = RtlGetAce(ExistingDacl, i, (PVOID *)&ExistingAce);
            if (!NT_SUCCESS(Status))
                goto Cleanup;
            Status = RtlAddAce(Dacl, Dacl->AclRevision, MAXULONG,
                               ExistingAce, ExistingAce->AceSize);
            if (!NT_SUCCESS(Status))
                goto Cleanup;
        }
    }

    Status = RtlAddAccessAllowedAceEx(
        Dacl, Dacl->AclRevision,
        OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
        FILE_ALL_ACCESS, UserInfo->User.Sid);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(AbsoluteDescriptor, TRUE,
                                              Dacl, DaclDefaulted);
    if (NT_SUCCESS(Status))
        Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor, NULL,
                                             &RelativeLength);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        RelativeDescriptor = MyAllocatePool__(PagedPool, RelativeLength);
        if (!RelativeDescriptor) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }
        Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor,
                                             RelativeDescriptor,
                                             &RelativeLength);
    }
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    OriginalDescriptor = *SecurityDescriptor;
    UpdatedDescriptor = OriginalDescriptor;
    Status = SeSetSecurityDescriptorInfo(
        NULL, &SecurityInformation, RelativeDescriptor,
        &UpdatedDescriptor, PagedPool, IoGetFileObjectGenericMapping());
    if (NT_SUCCESS(Status)) {
        if (UpdatedDescriptor != OriginalDescriptor)
            ExFreePool(OriginalDescriptor);
        *SecurityDescriptor = UpdatedDescriptor;
    } else if (UpdatedDescriptor != OriginalDescriptor) {
        ExFreePool(UpdatedDescriptor);
    }

Cleanup:
    if (UserInfo)
        ExFreePool(UserInfo);
    if (RelativeDescriptor)
        MyFreePool__(RelativeDescriptor);
    if (AbsoluteDescriptor)
        MyFreePool__(AbsoluteDescriptor);
    return Status;
}

static NTSTATUS
UDFAddRecycleBinMandatoryLabel(
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR AbsoluteDescriptor = NULL;
    PSECURITY_DESCRIPTOR RelativeDescriptor = NULL;
    PSECURITY_DESCRIPTOR OriginalDescriptor;
    PSECURITY_DESCRIPTOR UpdatedDescriptor;
    PACL ExistingSacl = NULL;
    PACL Sacl;
    BOOLEAN SaclPresent;
    BOOLEAN SaclDefaulted;
    BOOLEAN LabelPresent = FALSE;
    SID_IDENTIFIER_AUTHORITY MandatoryLabelAuthority =
        SECURITY_MANDATORY_LABEL_AUTHORITY;
    SID LowMandatorySid;
    ULONG AceLength;
    ULONG SaclLength;
    ULONG AbsoluteLength;
    ULONG RelativeLength = 0;
    ULONG ExistingAceLength = 0;
    ULONG SaclRevision = ACL_REVISION;
    ULONG i;
    PVOID Ace = NULL;
    PSYSTEM_MANDATORY_LABEL_ACE MandatoryAce;
    SECURITY_INFORMATION SecurityInformation = SACL_SECURITY_INFORMATION;

    Status = RtlInitializeSid(&LowMandatorySid, &MandatoryLabelAuthority, 1);
    if (!NT_SUCCESS(Status))
        return Status;
    *RtlSubAuthoritySid(&LowMandatorySid, 0) = SECURITY_MANDATORY_LOW_RID;

    Status = RtlGetSaclSecurityDescriptor(*SecurityDescriptor, &SaclPresent,
                                          &ExistingSacl, &SaclDefaulted);
    if (!NT_SUCCESS(Status))
        return Status;

    if (ExistingSacl) {
        SaclRevision = ExistingSacl->AclRevision;
        for (i = 0; i < ExistingSacl->AceCount; i++) {
            PACE_HEADER ExistingAce;

            Status = RtlGetAce(ExistingSacl, i, (PVOID *)&ExistingAce);
            if (!NT_SUCCESS(Status))
                return Status;
            ExistingAceLength += ExistingAce->AceSize;
            if (ExistingAce->AceType == SYSTEM_MANDATORY_LABEL_ACE_TYPE &&
                ExistingAce->AceSize >=
                    FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) +
                    RtlLengthSid(&LowMandatorySid)) {
                PSYSTEM_MANDATORY_LABEL_ACE ExistingMandatoryAce =
                    (PSYSTEM_MANDATORY_LABEL_ACE)ExistingAce;

                if (ExistingMandatoryAce->Mask ==
                        SYSTEM_MANDATORY_LABEL_NO_WRITE_UP &&
                (ExistingMandatoryAce->Header.AceFlags & ~INHERITED_ACE) ==
                        (OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                         INHERIT_ONLY_ACE) &&
                    RtlEqualSid((PSID)&ExistingMandatoryAce->SidStart,
                                &LowMandatorySid)) {
                    LabelPresent = TRUE;
                }
            }
        }
    }
    if (LabelPresent)
        return STATUS_SUCCESS;

    AceLength = FIELD_OFFSET(SYSTEM_MANDATORY_LABEL_ACE, SidStart) +
                RtlLengthSid(&LowMandatorySid);
    SaclLength = sizeof(ACL) + ExistingAceLength + AceLength;
    if (SaclLength > MAXUSHORT)
        return STATUS_INVALID_SECURITY_DESCR;

    AbsoluteLength = sizeof(SECURITY_DESCRIPTOR) + SaclLength;
    AbsoluteDescriptor = MyAllocatePool__(PagedPool, AbsoluteLength);
    if (!AbsoluteDescriptor)
        return STATUS_INSUFFICIENT_RESOURCES;

    Sacl = (PACL)((PUCHAR)AbsoluteDescriptor + sizeof(SECURITY_DESCRIPTOR));
    Status = RtlCreateSecurityDescriptor(AbsoluteDescriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Sacl, SaclLength, SaclRevision);

    if (NT_SUCCESS(Status) && ExistingSacl) {
        for (i = 0; i < ExistingSacl->AceCount; i++) {
            PACE_HEADER ExistingAce;

            Status = RtlGetAce(ExistingSacl, i, (PVOID *)&ExistingAce);
            if (!NT_SUCCESS(Status))
                break;
            Status = RtlAddAce(Sacl, SaclRevision, MAXULONG,
                               ExistingAce, ExistingAce->AceSize);
            if (!NT_SUCCESS(Status))
                break;
        }
    }

    if (NT_SUCCESS(Status)) {
        Ace = MyAllocatePool__(PagedPool, AceLength);
        if (!Ace) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            MandatoryAce = (PSYSTEM_MANDATORY_LABEL_ACE)Ace;
            MandatoryAce->Header.AceType = SYSTEM_MANDATORY_LABEL_ACE_TYPE;
            MandatoryAce->Header.AceFlags =
                OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE |
                INHERIT_ONLY_ACE;
            MandatoryAce->Header.AceSize = (USHORT)AceLength;
            MandatoryAce->Mask = SYSTEM_MANDATORY_LABEL_NO_WRITE_UP;
            Status = RtlCopySid(RtlLengthSid(&LowMandatorySid),
                                (PSID)&MandatoryAce->SidStart,
                                &LowMandatorySid);
            if (NT_SUCCESS(Status))
                Status = RtlAddAce(Sacl, SaclRevision, MAXULONG,
                                   Ace, AceLength);
        }
    }

    if (NT_SUCCESS(Status))
        Status = RtlSetSaclSecurityDescriptor(AbsoluteDescriptor, TRUE,
                                              Sacl, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor, NULL,
                                             &RelativeLength);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        RelativeDescriptor = MyAllocatePool__(PagedPool, RelativeLength);
        if (!RelativeDescriptor) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor,
                                                 RelativeDescriptor,
                                                 &RelativeLength);
        }
    }

    if (NT_SUCCESS(Status)) {
        OriginalDescriptor = *SecurityDescriptor;
        UpdatedDescriptor = OriginalDescriptor;
        Status = SeSetSecurityDescriptorInfo(
            NULL, &SecurityInformation, RelativeDescriptor,
            &UpdatedDescriptor, PagedPool,
            IoGetFileObjectGenericMapping());
        if (NT_SUCCESS(Status)) {
            if (UpdatedDescriptor != OriginalDescriptor)
                ExFreePool(OriginalDescriptor);
            *SecurityDescriptor = UpdatedDescriptor;
        } else if (UpdatedDescriptor != OriginalDescriptor) {
            ExFreePool(UpdatedDescriptor);
        }
    }

    if (Ace)
        MyFreePool__(Ace);
    if (RelativeDescriptor)
        MyFreePool__(RelativeDescriptor);
    if (AbsoluteDescriptor)
        MyFreePool__(AbsoluteDescriptor);
    return Status;
}

static NTSTATUS
UDFResolveSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo,
    ULONG Depth,
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    );

NTSTATUS
UDFCheckAccessRights(
    PIRP_CONTEXT IrpContext,
    PFILE_OBJECT FileObject, // OPTIONAL
    PACCESS_STATE AccessState,
    PFCB Fcb,
    PCCB Ccb,        // OPTIONAL
    ACCESS_MASK DesiredAccess,
    USHORT ShareAccess
    )
{
    NTSTATUS RC;
    BOOLEAN ROCheck = FALSE;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;

    // Check attr compatibility
    ASSERT(Fcb);
    ASSERT(Fcb->Vcb);

    if (Fcb->FcbState & UDF_FCB_READ_ONLY) {
        ROCheck = TRUE;
    } else
    if ((Fcb->Vcb->origIntegrityType == INTEGRITY_TYPE_OPEN) &&
        Fcb != Fcb->Vcb->VolumeDasdFcb && //TODO: TypeOfOpen != UserVolumeOpen
        (Fcb->Vcb->CompatFlags & UDF_VCB_IC_DIRTY_RO)) {

        AdPrint(("force R/O on dirty\n"));
        ROCheck = TRUE;
    } if (ROCheck) {

        //
        //  Check the desired access for a read-only dirent.  AccessMask will contain
        //  the flags we're going to allow.
        //

        ACCESS_MASK AccessMask = DELETE | READ_CONTROL | WRITE_OWNER | WRITE_DAC |
                            SYNCHRONIZE | ACCESS_SYSTEM_SECURITY | FILE_READ_DATA |
                            FILE_READ_EA | FILE_WRITE_EA | FILE_READ_ATTRIBUTES |
                            FILE_WRITE_ATTRIBUTES | FILE_EXECUTE | FILE_LIST_DIRECTORY |
                            FILE_TRAVERSE;

        //
        //  If this is a subdirectory also allow add file/directory and delete.
        //

        if (FlagOn(Fcb->FcbState, UDF_FCB_DIRECTORY)) {

            AccessMask |= FILE_ADD_SUBDIRECTORY | FILE_ADD_FILE | FILE_DELETE_CHILD;
        }

        if (FlagOn(DesiredAccess, ~AccessMask)) {

            AdPrint(("Cannot open readonly\n"));

            return STATUS_ACCESS_DENIED;
        }
    }

    if (AccessState && DesiredAccess) {
        ACCESS_MASK GrantedAccess = 0;
        NTSTATUS AccessStatus = STATUS_SUCCESS;
        BOOLEAN AccessGranted;

        RC = UDFResolveSecurityDescriptor(IrpContext, Fcb->Vcb, Fcb->FileInfo,
                                           0, &SecurityDescriptor);
        if (!NT_SUCCESS(RC))
            return RC;

        AccessGranted = SeAccessCheck(
            SecurityDescriptor,
            &AccessState->SubjectSecurityContext,
            FALSE,
            DesiredAccess,
            0,
            NULL,
            IoGetFileObjectGenericMapping(),
            IrpContext && IrpContext->Irp ?
                IrpContext->Irp->RequestorMode : UserMode,
            &GrantedAccess,
            &AccessStatus);
        MyFreePool__(SecurityDescriptor);
        if (!AccessGranted) {
            UDFPrintErr(("UDF access check denied %08x for %p, desired %08x\n",
                         AccessStatus, Fcb->FileInfo, DesiredAccess));
            return AccessStatus;
        }
    }

    if (FileObject) {
        if (Fcb->FcbCleanup) {
            // The FCB is currently in use by some thread.
            // We must check whether the requested access/share access
            // conflicts with the existing open operations.
            // Use Update=FALSE (check only, don't update ShareAccess).
            // IoSetShareAccess/IoUpdateShareAccess in UDFCompleteFcbOpen
            // handles the actual update AFTER all checks pass.
            RC = IoCheckShareAccess(DesiredAccess, ShareAccess, FileObject,
                                            &Fcb->ShareAccess, FALSE);
        } else {

            RC = STATUS_SUCCESS;
        }
    } else {
        // we get here if given file was opened for internal purposes
        RC = STATUS_SUCCESS;
    }
    return RC;
} // end UDFCheckAccessRights()

NTSTATUS
UDFSetAccessRights(
    PIRP_CONTEXT IrpContext,
    PFILE_OBJECT FileObject,
    PACCESS_STATE AccessState,
    PFCB Fcb,
    PCCB         Ccb,
    ACCESS_MASK  DesiredAccess,
    USHORT       ShareAccess
    )
{
    ASSERT(Ccb);
    ASSERT(Fcb->FileInfo);

    return UDFCheckAccessRights(IrpContext, FileObject, AccessState, Fcb, Ccb,
                                DesiredAccess, ShareAccess);

} // end UDFSetAccessRights()

static NTSTATUS
UDFReadSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo,
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    NTSTATUS Status;
    PUDF_FILE_INFO StreamDirInfo = NULL;
    PUDF_FILE_INFO AclInfo = NULL;
    int64 FileSize;
    BOOLEAN StreamDirOpened = FALSE;
    BOOLEAN AclOpened = FALSE;

    *SecurityDescriptor = NULL;
    if (!FileInfo)
        return STATUS_NO_SECURITY_ON_OBJECT;

    Status = UDFOpenStreamDir__(IrpContext, Vcb, FileInfo, &StreamDirInfo);
    if (Status == STATUS_NOT_FOUND) {
        UDFPrint(("UDF security: no stream directory for %p\n", FileInfo));
        return STATUS_NO_SECURITY_ON_OBJECT;
    }
    if (!NT_SUCCESS(Status))
        UDFPrintErr(("UDF security: opening stream directory failed %08x for %p\n",
                     Status, FileInfo));
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    StreamDirOpened = TRUE;

    Status = UDFOpenFile__(IrpContext, Vcb, FALSE, TRUE, &UdfData.AclName,
                           StreamDirInfo, &AclInfo, NULL);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
        Status == STATUS_NOT_FOUND) {
        UDFPrint(("UDF security: no ACL stream for %p\n", FileInfo));
        Status = STATUS_NO_SECURITY_ON_OBJECT;
        goto Cleanup;
    }
    if (!NT_SUCCESS(Status))
        UDFPrintErr(("UDF security: opening ACL stream failed %08x for %p\n",
                     Status, FileInfo));
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    AclOpened = TRUE;

    FileSize = UDFGetFileSize(AclInfo);
    if (FileSize < sizeof(SECURITY_DESCRIPTOR_RELATIVE) ||
        FileSize > 1024 * 1024) {
        UDFPrintErr(("UDF security: invalid ACL stream size %I64d for %p\n",
                     FileSize, FileInfo));
        Status = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    *SecurityDescriptor = MyAllocatePool__(PagedPool, (SIZE_T)FileSize);
    if (!*SecurityDescriptor) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Status = UDFReadFile__(IrpContext, Vcb, AclInfo, 0, (SIZE_T)FileSize,
                           FALSE, (int8 *)*SecurityDescriptor);
    if (!NT_SUCCESS(Status))
        UDFPrintErr(("UDF security: reading ACL stream failed %08x for %p\n",
                     Status, FileInfo));
    if (NT_SUCCESS(Status) &&
        !RtlValidRelativeSecurityDescriptor(*SecurityDescriptor,
                                            (ULONG)FileSize, 0)) {
        UDFPrintErr(("UDF security: invalid stored descriptor for %p\n",
                     FileInfo));
        Status = STATUS_INVALID_SECURITY_DESCR;
    }

Cleanup:
    if (AclInfo) {
        if (AclOpened)
            UDFCloseFile__(IrpContext, Vcb, AclInfo);
        if (UDFCleanUpFile__(Vcb, AclInfo))
            MyFreePool__(AclInfo);
    }
    if (StreamDirInfo) {
        if (StreamDirOpened)
            UDFCloseFile__(IrpContext, Vcb, StreamDirInfo);
        if (UDFCleanUpFile__(Vcb, StreamDirInfo))
            MyFreePool__(StreamDirInfo);
    }
    if (!NT_SUCCESS(Status) && *SecurityDescriptor) {
        MyFreePool__(*SecurityDescriptor);
        *SecurityDescriptor = NULL;
    }

    return Status;
}

static NTSTATUS
UDFBuildDefaultSecurityDescriptor(
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR AbsoluteDescriptor;
    PSECURITY_DESCRIPTOR RelativeDescriptor;
    PACL Acl;
    ULONG AclLength = sizeof(ACL) +
                      sizeof(ACCESS_ALLOWED_ACE) +
                      RtlLengthSid(SeExports->SeLocalSystemSid) - sizeof(ULONG) +
                      sizeof(ACCESS_ALLOWED_ACE) +
                      RtlLengthSid(SeExports->SeAliasAdminsSid) - sizeof(ULONG) +
                      sizeof(ACCESS_ALLOWED_ACE) +
                      RtlLengthSid(SeExports->SeAuthenticatedUsersSid) - sizeof(ULONG);
    ULONG AbsoluteLength = sizeof(SECURITY_DESCRIPTOR) + AclLength;
    ULONG RelativeLength = 0;

    AbsoluteDescriptor = MyAllocatePool__(PagedPool, AbsoluteLength);
    if (!AbsoluteDescriptor)
        return STATUS_INSUFFICIENT_RESOURCES;

    Acl = (PACL)((PUCHAR)AbsoluteDescriptor + sizeof(SECURITY_DESCRIPTOR));
    Status = RtlCreateSecurityDescriptor(AbsoluteDescriptor,
                                         SECURITY_DESCRIPTOR_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlSetOwnerSecurityDescriptor(AbsoluteDescriptor,
                                               SeExports->SeAliasAdminsSid, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlSetGroupSecurityDescriptor(AbsoluteDescriptor,
                                               SeExports->SeLocalSystemSid, FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlCreateAcl(Acl, AclLength, ACL_REVISION);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAceEx(
            Acl, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS, SeExports->SeLocalSystemSid);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAceEx(
            Acl, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_ALL_ACCESS, SeExports->SeAliasAdminsSid);
    if (NT_SUCCESS(Status))
        Status = RtlAddAccessAllowedAceEx(
            Acl, ACL_REVISION, OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE,
            FILE_GENERIC_READ | FILE_GENERIC_WRITE | FILE_GENERIC_EXECUTE |
                DELETE | FILE_DELETE_CHILD | FILE_ADD_FILE | FILE_ADD_SUBDIRECTORY,
            SeExports->SeAuthenticatedUsersSid);
    if (NT_SUCCESS(Status))
        Status = RtlSetDaclSecurityDescriptor(AbsoluteDescriptor, TRUE, Acl,
                                              FALSE);
    if (NT_SUCCESS(Status))
        Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor, NULL,
                                             &RelativeLength);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        RelativeDescriptor = MyAllocatePool__(PagedPool, RelativeLength);
        if (!RelativeDescriptor) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
        } else {
            Status = RtlAbsoluteToSelfRelativeSD(AbsoluteDescriptor,
                                                 RelativeDescriptor,
                                                 &RelativeLength);
            if (NT_SUCCESS(Status))
                *SecurityDescriptor = RelativeDescriptor;
            else
                MyFreePool__(RelativeDescriptor);
        }
    }
    MyFreePool__(AbsoluteDescriptor);
    return Status;
}

static NTSTATUS
UDFResolveSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo,
    ULONG Depth,
    PSECURITY_DESCRIPTOR *SecurityDescriptor
    )
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR ParentDescriptor = NULL;
    PSECURITY_DESCRIPTOR InheritedDescriptor = NULL;
    PSECURITY_DESCRIPTOR RelativeDescriptor = NULL;
    SECURITY_SUBJECT_CONTEXT SubjectContext;
    SECURITY_INFORMATION SecurityInformation =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    ULONG BufferLength;

    Status = UDFReadSecurityDescriptor(IrpContext, Vcb, FileInfo,
                                       SecurityDescriptor);
    if (Status != STATUS_NO_SECURITY_ON_OBJECT)
        return Status;

    if (Depth >= 32)
        return STATUS_ACCESS_DENIED;
    if (!FileInfo || !FileInfo->ParentFile || FileInfo->ParentFile == FileInfo) {
        UDFPrint(("UDF security: using default descriptor for %p\n", FileInfo));
        return UDFBuildDefaultSecurityDescriptor(SecurityDescriptor);
    }

    Status = UDFResolveSecurityDescriptor(IrpContext, Vcb,
                                          FileInfo->ParentFile, Depth + 1,
                                          &ParentDescriptor);
    if (!NT_SUCCESS(Status))
        return Status;

    SeCaptureSubjectContext(&SubjectContext);
    Status = SeAssignSecurityEx(
        ParentDescriptor, NULL, &InheritedDescriptor, NULL,
        UDFIsADirectory(FileInfo),
        SEF_DEFAULT_GROUP_FROM_PARENT |
            SEF_DACL_AUTO_INHERIT | SEF_SACL_AUTO_INHERIT,
        &SubjectContext, IoGetFileObjectGenericMapping(), PagedPool);
    SeReleaseSubjectContext(&SubjectContext);
    MyFreePool__(ParentDescriptor);
    if (!NT_SUCCESS(Status)) {
        UDFPrintErr(("UDF security: inheriting descriptor failed %08x for %p\n",
                     Status, FileInfo));
        return Status;
    }

    BufferLength = RtlLengthSecurityDescriptor(InheritedDescriptor);
    RelativeDescriptor = MyAllocatePool__(PagedPool, BufferLength);
    if (!RelativeDescriptor) {
        ExFreePool(InheritedDescriptor);
        return STATUS_INSUFFICIENT_RESOURCES;
    }

    Status = SeQuerySecurityDescriptorInfo(&SecurityInformation,
                                           RelativeDescriptor,
                                           &BufferLength,
                                           &InheritedDescriptor);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        if (!BufferLength || BufferLength > 1024 * 1024) {
            Status = STATUS_INVALID_SECURITY_DESCR;
            MyFreePool__(RelativeDescriptor);
            ExFreePool(InheritedDescriptor);
            return Status;
        }
        MyFreePool__(RelativeDescriptor);
        RelativeDescriptor = MyAllocatePool__(PagedPool, BufferLength);
        if (!RelativeDescriptor) {
            ExFreePool(InheritedDescriptor);
            return STATUS_INSUFFICIENT_RESOURCES;
        }
        Status = SeQuerySecurityDescriptorInfo(&SecurityInformation,
                                               RelativeDescriptor,
                                               &BufferLength,
                                               &InheritedDescriptor);
    }
    ExFreePool(InheritedDescriptor);
    if (!NT_SUCCESS(Status)) {
        UDFPrintErr(("UDF security: converting inherited descriptor failed %08x for %p\n",
                     Status, FileInfo));
        MyFreePool__(RelativeDescriptor);
        return Status;
    }

    *SecurityDescriptor = RelativeDescriptor;
    return STATUS_SUCCESS;
}

static NTSTATUS
UDFWriteSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO FileInfo,
    PSECURITY_DESCRIPTOR SecurityDescriptor
    )
{
    NTSTATUS Status;
    PUDF_FILE_INFO StreamDirInfo = NULL;
    PUDF_FILE_INFO AclInfo = NULL;
    SIZE_T WrittenBytes;
    ULONG SecurityDescriptorLength = RtlLengthSecurityDescriptor(SecurityDescriptor);
    BOOLEAN StreamDirOpened = FALSE;
    BOOLEAN AclOpened = FALSE;

    Status = UDFOpenStreamDir__(IrpContext, Vcb, FileInfo, &StreamDirInfo);
    if (Status == STATUS_NOT_FOUND) {
        Status = UDFCreateStreamDir__(IrpContext, Vcb, FileInfo, &StreamDirInfo);
    }
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    StreamDirOpened = TRUE;

    Status = UDFOpenFile__(IrpContext, Vcb, FALSE, TRUE, &UdfData.AclName,
                           StreamDirInfo, &AclInfo, NULL);
    if (Status == STATUS_OBJECT_NAME_NOT_FOUND ||
        Status == STATUS_NOT_FOUND) {
        Status = UDFCreateFile__(IrpContext, Vcb, FALSE, &UdfData.AclName,
                                 0, 0, FALSE, FALSE, StreamDirInfo, &AclInfo);
    }
    if (!NT_SUCCESS(Status))
        goto Cleanup;
    AclOpened = TRUE;

    Status = UDFWriteFile__(IrpContext, Vcb, AclInfo, 0,
                            SecurityDescriptorLength, FALSE,
                            (int8 *)SecurityDescriptor, &WrittenBytes);
    if (NT_SUCCESS(Status) && WrittenBytes != SecurityDescriptorLength)
        Status = STATUS_DISK_FULL;
    if (NT_SUCCESS(Status))
        Status = UDFResizeFile__(IrpContext, Vcb, AclInfo,
                                 SecurityDescriptorLength);

Cleanup:
    if (AclInfo) {
        if (AclOpened) {
            NTSTATUS CloseStatus = UDFCloseFile__(IrpContext, Vcb, AclInfo);
            if (NT_SUCCESS(Status))
                Status = CloseStatus;
        }
        if (UDFCleanUpFile__(Vcb, AclInfo))
            MyFreePool__(AclInfo);
    }
    if (StreamDirInfo) {
        if (StreamDirOpened) {
            NTSTATUS CloseStatus = UDFCloseFile__(IrpContext, Vcb, StreamDirInfo);
            if (NT_SUCCESS(Status))
                Status = CloseStatus;
        }
        if (UDFCleanUpFile__(Vcb, StreamDirInfo))
            MyFreePool__(StreamDirInfo);
    }

    return Status;
}

NTSTATUS
UDFCreateSecurityDescriptor(
    PIRP_CONTEXT IrpContext,
    PVCB Vcb,
    PUDF_FILE_INFO ParentFileInfo,
    PUDF_FILE_INFO FileInfo,
    PACCESS_STATE AccessState
    )
{
    NTSTATUS Status;
    PSECURITY_DESCRIPTOR ParentDescriptor = NULL;
    PSECURITY_DESCRIPTOR AssignedDescriptor = NULL;
    PSECURITY_DESCRIPTOR RelativeDescriptor = NULL;
    SECURITY_INFORMATION SecurityInformation =
        OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION |
        DACL_SECURITY_INFORMATION | SACL_SECURITY_INFORMATION;
    ULONG BufferLength;

    Status = UDFResolveSecurityDescriptor(IrpContext, Vcb, ParentFileInfo,
                                         0, &ParentDescriptor);
    if (!NT_SUCCESS(Status))
        goto Cleanup;

    Status = SeAssignSecurityEx(
        ParentDescriptor,
        AccessState->SecurityDescriptor,
        &AssignedDescriptor,
        NULL,
        UDFIsADirectory(FileInfo),
        SEF_DEFAULT_GROUP_FROM_PARENT |
            SEF_DACL_AUTO_INHERIT | SEF_SACL_AUTO_INHERIT,
        &AccessState->SubjectSecurityContext,
        IoGetFileObjectGenericMapping(),
        PagedPool);
    if (!NT_SUCCESS(Status)) {
        UDFPrintErr(("UDF security: assigning descriptor failed %08x for %p\n",
                     Status, FileInfo));
        goto Cleanup;
    }

    if (UDFIsADirectory(FileInfo)) {
        BOOLEAN IsRecycleBinRootDirectory =
            UDFIsRecycleBinDirectory(FileInfo, Vcb) ||
            UDFIsRecycleBinRoot(
                IoGetCurrentIrpStackLocation(IrpContext->Irp)->FileObject,
                Vcb, FileInfo);
        BOOLEAN IsRecycleBinChild =
            UDFIsRecycleBinDirectory(ParentFileInfo, Vcb);

        if (IsRecycleBinRootDirectory) {
            Status = UDFSetRecycleBinUsersInheritance(AssignedDescriptor);
            if (!NT_SUCCESS(Status)) {
                UDFPrintErr(("UDF security: setting Recycle Bin Users inheritance failed %08x\n",
                             Status));
                goto Cleanup;
            }
        } else if (IsRecycleBinChild) {
            Status = UDFAddRecycleBinCreatorAce(&AssignedDescriptor,
                                                AccessState);
            if (!NT_SUCCESS(Status)) {
                UDFPrintErr(("UDF security: adding Recycle Bin creator ACE failed %08x\n",
                             Status));
                goto Cleanup;
            }
        }

        if (IsRecycleBinRootDirectory || IsRecycleBinChild)
            Status = UDFAddRecycleBinMandatoryLabel(&AssignedDescriptor);
        if (!NT_SUCCESS(Status)) {
            UDFPrintErr(("UDF security: adding Recycle Bin label failed %08x\n",
                         Status));
            goto Cleanup;
        }
    }

    BufferLength = RtlLengthSecurityDescriptor(AssignedDescriptor);
    if (!BufferLength || BufferLength > 1024 * 1024) {
        Status = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    RelativeDescriptor = MyAllocatePool__(PagedPool, BufferLength);
    if (!RelativeDescriptor) {
        Status = STATUS_INSUFFICIENT_RESOURCES;
        goto Cleanup;
    }

    Status = SeQuerySecurityDescriptorInfo(&SecurityInformation,
                                           RelativeDescriptor,
                                           &BufferLength,
                                           &AssignedDescriptor);
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        MyFreePool__(RelativeDescriptor);
        RelativeDescriptor = MyAllocatePool__(PagedPool, BufferLength);
        if (!RelativeDescriptor) {
            Status = STATUS_INSUFFICIENT_RESOURCES;
            goto Cleanup;
        }

        Status = SeQuerySecurityDescriptorInfo(&SecurityInformation,
                                               RelativeDescriptor,
                                               &BufferLength,
                                               &AssignedDescriptor);
    }
    if (!NT_SUCCESS(Status)) {
        UDFPrintErr(("UDF security: serializing descriptor failed %08x for %p\n",
                     Status, FileInfo));
        goto Cleanup;
    }
    if (!RtlValidRelativeSecurityDescriptor(RelativeDescriptor,
                                            BufferLength, 0)) {
        Status = STATUS_INVALID_SECURITY_DESCR;
        goto Cleanup;
    }

    Status = UDFWriteSecurityDescriptor(IrpContext, Vcb, FileInfo,
                                        RelativeDescriptor);
    if (!NT_SUCCESS(Status))
        UDFPrintErr(("UDF security: storing created descriptor failed %08x for %p\n",
                     Status, FileInfo));

Cleanup:
    if (RelativeDescriptor)
        MyFreePool__(RelativeDescriptor);
    if (AssignedDescriptor)
        ExFreePool(AssignedDescriptor);
    if (ParentDescriptor)
        MyFreePool__(ParentDescriptor);
    return Status;
}

NTSTATUS
UDFCommonQuerySecurity(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    )
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PFCB Fcb = NULL;
    PCCB Ccb = NULL;
    PSECURITY_DESCRIPTOR SecurityDescriptor = NULL;
    PVOID Buffer = NULL;
    ULONG BufferLength = IrpSp->Parameters.QuerySecurity.Length;
    BOOLEAN FcbAcquired = FALSE;
    TYPE_OF_OPEN TypeOfOpen;

    Irp->IoStatus.Information = 0;
    UDFPrint(("UDF query security: file object %p information %08x length %lu\n",
              FileObject,
              IrpSp->Parameters.QuerySecurity.SecurityInformation,
              BufferLength));

    if (!FileObject) {
        Status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    TypeOfOpen = UDFDecodeFileObject(FileObject, &Fcb, &Ccb);
    if (TypeOfOpen != UserFileOpen && TypeOfOpen != UserDirectoryOpen) {
        Status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    if (!UDFAcquireFcbExclusive(IrpContext, Fcb, FALSE)) {
        Status = STATUS_CANT_WAIT;
        goto Complete;
    }
    FcbAcquired = TRUE;

    Status = UDFResolveSecurityDescriptor(IrpContext, Fcb->Vcb, Fcb->FileInfo,
                                          0, &SecurityDescriptor);
    if (!NT_SUCCESS(Status)) {
        UDFPrintErr(("UDF query security: resolving descriptor failed %08x for %wZ\n",
                     Status, &FileObject->FileName));
        goto Complete;
    }

    if (BufferLength) {
        Status = UDFLockUserBuffer(IrpContext, BufferLength, IoWriteAccess);
        if (!NT_SUCCESS(Status))
            goto Complete;
        Buffer = UDFMapUserBuffer(Irp);
        if (!Buffer) {
            Status = STATUS_INVALID_USER_BUFFER;
            goto Complete;
        }
    }

    _SEH2_TRY {
        Status = SeQuerySecurityDescriptorInfo(
            &IrpSp->Parameters.QuerySecurity.SecurityInformation,
            (PSECURITY_DESCRIPTOR)Buffer, &BufferLength,
            &SecurityDescriptor);
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        Status = _SEH2_GetExceptionCode();
    } _SEH2_END;
    if (Status == STATUS_BUFFER_TOO_SMALL) {
        Irp->IoStatus.Information = BufferLength;
        Status = STATUS_BUFFER_OVERFLOW;
    } else if (NT_SUCCESS(Status)) {
        Irp->IoStatus.Information = BufferLength;
    }

Complete:
    UDFPrint(("UDF query security: completed %08x length %lu for file object %p\n",
              Status, Irp->IoStatus.Information, FileObject));
    if (FcbAcquired)
        UDFReleaseFcb(IrpContext, Fcb);
    if (SecurityDescriptor)
        MyFreePool__(SecurityDescriptor);
    UDFCompleteRequest(IrpContext, Irp, Status);
    return Status;
}

NTSTATUS
UDFCommonSetSecurity(
    PIRP_CONTEXT IrpContext,
    PIRP Irp
    )
{
    NTSTATUS Status;
    PIO_STACK_LOCATION IrpSp = IoGetCurrentIrpStackLocation(Irp);
    PFILE_OBJECT FileObject = IrpSp->FileObject;
    PFCB Fcb = NULL;
    PCCB Ccb = NULL;
    PSECURITY_DESCRIPTOR ExistingDescriptor = NULL;
    PSECURITY_DESCRIPTOR UpdatedDescriptor = NULL;
    SECURITY_INFORMATION SecurityInformation =
        IrpSp->Parameters.SetSecurity.SecurityInformation;
    ACCESS_MASK DesiredAccess = 0;
    BOOLEAN FcbAcquired = FALSE;
    TYPE_OF_OPEN TypeOfOpen;

    Irp->IoStatus.Information = 0;
    UDFPrint(("UDF set security: file object %p information %08x\n",
              FileObject, SecurityInformation));

    if (!FileObject) {
        Status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    TypeOfOpen = UDFDecodeFileObject(FileObject, &Fcb, &Ccb);
    if (TypeOfOpen != UserFileOpen && TypeOfOpen != UserDirectoryOpen) {
        Status = STATUS_INVALID_PARAMETER;
        goto Complete;
    }

    if (SecurityInformation & (OWNER_SECURITY_INFORMATION |
                               GROUP_SECURITY_INFORMATION))
        DesiredAccess |= WRITE_OWNER;
    if (SecurityInformation & DACL_SECURITY_INFORMATION)
        DesiredAccess |= WRITE_DAC;
    if (SecurityInformation & SACL_SECURITY_INFORMATION)
        DesiredAccess |= ACCESS_SYSTEM_SECURITY;
    if (FlagOn(Fcb->FcbState, UDF_FCB_READ_ONLY) ||
        UDFIllegalFcbAccess(Fcb->Vcb, DesiredAccess)) {
        Status = STATUS_MEDIA_WRITE_PROTECTED;
        goto Complete;
    }

    if (!UDFAcquireFcbExclusive(IrpContext, Fcb, FALSE)) {
        Status = STATUS_CANT_WAIT;
        goto Complete;
    }
    FcbAcquired = TRUE;

    Status = UDFResolveSecurityDescriptor(IrpContext, Fcb->Vcb, Fcb->FileInfo,
                                          0, &ExistingDescriptor);
    if (!NT_SUCCESS(Status))
        goto Complete;

    UpdatedDescriptor = ExistingDescriptor;
    _SEH2_TRY {
        Status = SeSetSecurityDescriptorInfo(
            NULL, &SecurityInformation,
            IrpSp->Parameters.SetSecurity.SecurityDescriptor,
            &UpdatedDescriptor, PagedPool,
            IoGetFileObjectGenericMapping());
    } _SEH2_EXCEPT(EXCEPTION_EXECUTE_HANDLER) {
        Status = _SEH2_GetExceptionCode();
    } _SEH2_END;
    if (!NT_SUCCESS(Status))
        goto Complete;

    if (RtlLengthSecurityDescriptor(UpdatedDescriptor) > 1024 * 1024) {
        Status = STATUS_INVALID_SECURITY_DESCR;
        goto Complete;
    }

    Status = UDFWriteSecurityDescriptor(IrpContext, Fcb->Vcb, Fcb->FileInfo,
                                        UpdatedDescriptor);
    if (!NT_SUCCESS(Status))
        UDFPrintErr(("UDF set security: storing descriptor failed %08x for %p\n",
                     Status, Fcb->FileInfo));

Complete:
    UDFPrint(("UDF set security: completed %08x for file object %p\n",
              Status, FileObject));
    if (FcbAcquired)
        UDFReleaseFcb(IrpContext, Fcb);
    if (UpdatedDescriptor && UpdatedDescriptor != ExistingDescriptor)
        ExFreePool(UpdatedDescriptor);
    if (ExistingDescriptor)
        MyFreePool__(ExistingDescriptor);
    UDFCompleteRequest(IrpContext, Irp, Status);
    return Status;
}
