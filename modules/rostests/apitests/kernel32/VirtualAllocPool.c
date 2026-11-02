/*
 * PROJECT:     ReactOS api tests
 * LICENSE:     GPL-2.0-or-later (https://spdx.org/licenses/GPL-2.0-or-later)
 * PURPOSE:     Test a large reserve-then-commit VirtualAlloc pool (CORE-15087)
 * COPYRIGHT:   Copyright 2026 Fuad Amin Ishtiak
 */

#include "precomp.h"

/*
 * GTK-Gnutella reserves most of the free address space as one
 * PAGE_NOACCESS region at startup, commits pages inside it as it needs
 * them and only decommits them again. The whole region is released at
 * exit. CORE-15087 is about this pattern failing on ReactOS. The steps
 * below follow its startup code: probe how much can be reserved, size
 * the pool to 80% of that and reserve it, then commit, use and decommit
 * blocks of different sizes inside the pool.
 */

#define MIB             (1024 * 1024)
#define POOL_MIN_SIZE   (100 * MIB)
#define POOL_STEP       (4 * MIB)

static SYSTEM_INFO SysInfo;
static PUCHAR PoolBase;
static SIZE_T PoolSize;
static SIZE_T PoolUsed;

static SIZE_T
RoundToPage(SIZE_T Size)
{
    return (Size + SysInfo.dwPageSize - 1) & ~((SIZE_T)SysInfo.dwPageSize - 1);
}

/* Largest reservation that succeeds, stepping down from Size. */
static PVOID
ReserveLargest(SIZE_T Size, SIZE_T *Reserved)
{
    PVOID Base;

    for (; Size >= POOL_MIN_SIZE; Size -= POOL_STEP)
    {
        Base = VirtualAlloc(NULL, Size, MEM_RESERVE, PAGE_NOACCESS);
        if (Base)
        {
            *Reserved = Size;
            return Base;
        }
    }
    *Reserved = 0;
    return NULL;
}

static BOOL
CreatePool(void)
{
    SIZE_T AddressSpace, Available, Later = 0, Main = 0;
    PVOID LaterBase, MainBase;

    AddressSpace = (SIZE_T)SysInfo.lpMaximumApplicationAddress -
                   (SIZE_T)SysInfo.lpMinimumApplicationAddress;
    AddressSpace &= ~((SIZE_T)POOL_STEP - 1);

    /* Probe: a block for later use (at most 90% of the address space),
     * then the largest pool that still fits next to it. */
    LaterBase = ReserveLargest(AddressSpace / 10 * 9, &Later);
    ok(LaterBase != NULL, "Could not reserve %lu MiB, error %lu\n",
       (ULONG)(POOL_MIN_SIZE / MIB), GetLastError());
    if (!LaterBase)
        return FALSE;
    MainBase = ReserveLargest(AddressSpace - Later, &Main);
    ok(VirtualFree(LaterBase, 0, MEM_RELEASE), "Release failed, error %lu\n", GetLastError());
    if (MainBase)
        ok(VirtualFree(MainBase, 0, MEM_RELEASE), "Release failed, error %lu\n", GetLastError());

    /* Final pool: 80% of what could be reserved in total. */
    Available = Later + Main;
    PoolSize = RoundToPage(Available / 10 * 8);
    PoolBase = VirtualAlloc(NULL, PoolSize, MEM_RESERVE, PAGE_NOACCESS);
    if (!PoolBase)
    {
        PoolSize = POOL_MIN_SIZE;
        PoolBase = VirtualAlloc(NULL, PoolSize, MEM_RESERVE, PAGE_NOACCESS);
    }
    ok(PoolBase != NULL, "Could not reserve the %lu MiB pool, error %lu\n",
       (ULONG)(PoolSize / MIB), GetLastError());
    trace("Probed %lu MiB, pool %lu MiB at %p\n",
          (ULONG)(Available / MIB), (ULONG)(PoolSize / MIB), PoolBase);
    PoolUsed = 0;
    return PoolBase != NULL;
}

static PUCHAR
PoolCommit(SIZE_T Size)
{
    PUCHAR Block;

    Size = RoundToPage(Size);
    if (PoolUsed + Size > PoolSize)
        return NULL;
    Block = VirtualAlloc(PoolBase + PoolUsed, Size, MEM_COMMIT, PAGE_READWRITE);
    ok(Block == PoolBase + PoolUsed, "Commit of %lu KiB at %p returned %p, error %lu\n",
       (ULONG)(Size / 1024), PoolBase + PoolUsed, Block, GetLastError());
    if (Block)
        PoolUsed += Size;
    return Block;
}

static void
PoolDecommit(PUCHAR Block, SIZE_T Size)
{
    MEMORY_BASIC_INFORMATION Info;

    Size = RoundToPage(Size);
    ok(VirtualFree(Block, Size, MEM_DECOMMIT), "Decommit of %lu KiB failed, error %lu\n",
       (ULONG)(Size / 1024), GetLastError());
    ok(VirtualQuery(Block, &Info, sizeof(Info)) == sizeof(Info), "VirtualQuery failed\n");
    ok(Info.State == MEM_RESERVE, "Decommitted block is in state %lx\n", Info.State);
}

static void
TestBlock(SIZE_T Size)
{
    PUCHAR Block = PoolCommit(Size);
    SIZE_T i;

    if (!Block)
        return;
    for (i = 0; i < Size; i += SysInfo.dwPageSize)
        Block[i] = (UCHAR)(i / SysInfo.dwPageSize);
    for (i = 0; i < Size; i += SysInfo.dwPageSize)
    {
        if (Block[i] != (UCHAR)(i / SysInfo.dwPageSize))
        {
            ok(0, "Read back wrong data at offset %lu of %lu KiB block\n",
               (ULONG)i, (ULONG)(Size / 1024));
            break;
        }
    }
    PoolDecommit(Block, Size);
}

START_TEST(VirtualAllocPool)
{
    static const SIZE_T Sizes[] =
        { 4096, 64 * 1024, 256 * 1024, 1 * MIB, 4 * MIB, 16 * MIB, 64 * MIB };
    PUCHAR A, B, C;
    ULONG i;

    GetSystemInfo(&SysInfo);
    if (!CreatePool())
        return;

    for (i = 0; i < _countof(Sizes); i++)
        TestBlock(Sizes[i]);

    /* Several blocks committed at the same time. */
    A = PoolCommit(1 * MIB);
    B = PoolCommit(4 * MIB);
    C = PoolCommit(16 * MIB);
    if (A && B && C)
    {
        memset(A, 0xAA, 1 * MIB);
        memset(B, 0xBB, 4 * MIB);
        memset(C, 0xCC, 16 * MIB);
        ok(A[1 * MIB - 1] == 0xAA && B[0] == 0xBB && C[16 * MIB - 1] == 0xCC,
           "Committed blocks overlap\n");
    }
    if (C) PoolDecommit(C, 16 * MIB);
    if (B) PoolDecommit(B, 4 * MIB);
    if (A) PoolDecommit(A, 1 * MIB);

    ok(VirtualFree(PoolBase, 0, MEM_RELEASE), "Releasing the pool failed, error %lu\n",
       GetLastError());
}
