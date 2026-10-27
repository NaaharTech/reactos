/* Native UDF 2.50 formatting provider. */
#pragma once
#include <fmifs/fmifs.h>
BOOLEAN NTAPI UdfFormat(PUNICODE_STRING DriveRoot, PFMIFSCALLBACK Callback,
                       BOOLEAN QuickFormat, BOOLEAN BackwardCompatible,
                       MEDIA_TYPE MediaType, PUNICODE_STRING Label, ULONG ClusterSize);
