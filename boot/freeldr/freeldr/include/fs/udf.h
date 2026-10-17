/* Read-only UDF 2.50 metadata-partition support for FreeLoader. */
#pragma once

const DEVVTBL* UdfMount(ULONG DeviceId);
ULONGLONG UdfGetVolumeSize(ULONG DeviceId);
