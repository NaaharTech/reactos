#include "recovery_core.h"

#include <string.h>

typedef struct _RECOVERY_EXTENT {
    uint32_t Lbn;
    uint32_t Blocks;
    uint32_t Bytes;
    uint16_t Ref;
} RECOVERY_EXTENT;

typedef struct _RECOVERY_EXTENT_LIST {
    RECOVERY_EXTENT Items[UDFS_RECOVERY_MAX_EXTENTS];
    uint32_t Count;
    uint32_t TotalBlocks;
    uint64_t FileBytes;
    uint32_t InlineFeLbn;
    uint32_t InlineOffset;
    uint8_t Inline;
} RECOVERY_EXTENT_LIST;

typedef struct _RECOVERY_SECTOR_CACHE {
    uint32_t Lba;
    uint8_t Data[UDFS_RECOVERY_SECTOR_SIZE];
    int Valid;
} RECOVERY_SECTOR_CACHE;

static uint16_t
Read16(const uint8_t *p)
{
    return (uint16_t)(p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t
Read32(const uint8_t *p)
{
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t
Read64(const uint8_t *p)
{
    return (uint64_t)Read32(p) | ((uint64_t)Read32(p + 4) << 32);
}

static int
RecoveryDifference(const void *left, const void *right, size_t length)
{
    const uint8_t *a = (const uint8_t *)left;
    const uint8_t *b = (const uint8_t *)right;
    uint8_t difference = 0;
    size_t i;
    for (i = 0; i < length; ++i)
        difference |= a[i] ^ b[i];
    return difference;
}

static void
Write16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void
Write32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

static void
Write64(uint8_t *p, uint64_t value)
{
    Write32(p, (uint32_t)value);
    Write32(p + 4, (uint32_t)(value >> 32));
}

static uint16_t
TagCrc(const uint8_t *p, uint32_t length)
{
    uint16_t crc = 0;
    uint32_t i;
    for (i = 0; i < length; ++i) {
        uint32_t bit;
        crc ^= (uint16_t)p[i] << 8;
        for (bit = 0; bit < 8; ++bit)
            crc = (uint16_t)((crc << 1) ^ ((crc & 0x8000) ? 0x1021 : 0));
    }
    return crc;
}

static UDFS_RECOVERY_PROBE_STATUS
ReadSector(const UDFS_RECOVERY_READER *reader, UDFS_RECOVERY_PROBE *result,
           uint32_t lba, uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE])
{
    if (lba >= reader->SectorCount) {
        result->FailureLba = lba;
        return UdfsRecoveryProbeCorrupt;
    }
    if (reader->ReadSector(reader->Context, lba, sector) != 0) {
        result->FailureLba = lba;
        return UdfsRecoveryProbeIoError;
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
ValidateTag(const uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE],
            uint16_t kind, uint32_t location)
{
    uint32_t i, checksum = 0;
    uint16_t crcLength = Read16(sector + 10);

    if (Read16(sector) != kind || Read32(sector + 12) != location ||
        (Read16(sector + 2) != 2 && Read16(sector + 2) != 3))
        return UdfsRecoveryProbeCorrupt;
    if (crcLength > UDFS_RECOVERY_SECTOR_SIZE - 16)
        return UdfsRecoveryProbeUnsupported;
    for (i = 0; i < 16; ++i)
        if (i != 4) checksum += sector[i];
    if ((uint8_t)checksum != sector[4] ||
        TagCrc(sector + 16, crcLength) != Read16(sector + 8))
        return UdfsRecoveryProbeCorrupt;
    return UdfsRecoveryProbeValidLayout;
}

/* A linked final OPEN LVID can have only its tag-checksum byte torn while
 * its CRC-covered body is intact. Normalize that one byte in memory so the
 * complete owner graph can decide whether a repair is safe. The raw sector
 * remains the compare-before-write value; no other damaged tag is accepted. */
static UDFS_RECOVERY_PROBE_STATUS
NormalizeOpenLvidTagChecksum(uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE],
                             uint32_t lba, int allow, uint8_t *repaired)
{
    UDFS_RECOVERY_PROBE_STATUS status = ValidateTag(sector, 9, lba);
    uint32_t i, checksum = 0;
    uint8_t oldChecksum;

    if (repaired) *repaired = 0;
    if (status != UdfsRecoveryProbeCorrupt || !allow)
        return status;
    if (Read16(sector + 10) < 136 - 16 ||
        Read32(sector + 28) != 0 ||
        Read32(sector + 32) != 0 || Read32(sector + 36) != 0)
        return status;
    for (i = 0; i < 16; ++i)
        if (i != 4) checksum += sector[i];
    oldChecksum = sector[4];
    if (oldChecksum == (uint8_t)checksum)
        return status;
    sector[4] = (uint8_t)checksum;
    status = ValidateTag(sector, 9, lba);
    if (status != UdfsRecoveryProbeValidLayout) {
        sector[4] = oldChecksum;
        return status;
    }
    if (repaired) *repaired = 1;
    return status;
}

/* A split mirror is recoverable only when both complete, CRC-valid directory
 * FEs differ solely in the link count and its tag CRC/checksum.  The
 * namespace walk later decides which count is correct; no copy wins merely
 * because it is primary or newer-looking. */
static int
DirectoryFePairDiffersOnlyInLinkCount(
    const uint8_t main[UDFS_RECOVERY_SECTOR_SIZE],
    const uint8_t mirror[UDFS_RECOVERY_SECTOR_SIZE], uint32_t lbn)
{
    uint16_t kind = Read16(main), a = Read16(main + 48);
    uint16_t b = Read16(mirror + 48);
    uint32_t i;
    if ((kind != 261 && kind != 266) || Read16(mirror) != kind ||
        main[27] != 4 || mirror[27] != 4 ||
        Read16(main + 10) < 50 - 16 ||
        Read16(mirror + 10) < 50 - 16 ||
        ValidateTag(main, kind, lbn) != UdfsRecoveryProbeValidLayout ||
        ValidateTag(mirror, kind, lbn) != UdfsRecoveryProbeValidLayout ||
        (a + 1 != b && b + 1 != a))
        return 0;
    for (i = 0; i < UDFS_RECOVERY_SECTOR_SIZE; ++i)
        if (i != 4 && i != 8 && i != 9 && i != 48 && i != 49 &&
            main[i] != mirror[i])
            return 0;
    return 1;
}

static int
ValidFidRecordInSector(const uint8_t *fid, uint32_t available,
                       uint32_t lbn, uint32_t *recordLength)
{
    uint32_t raw, length, crcLength, checksum = 0, i;
    if (available < 40 || Read16(fid) != 257 ||
        (Read16(fid + 2) != 2 && Read16(fid + 2) != 3) ||
        Read16(fid + 16) != 1 || Read32(fid + 12) != lbn ||
        (fid[18] & ~0x1fU))
        return 0;
    raw = 38 + Read16(fid + 36) + fid[19];
    length = (raw + 3) & ~3U;
    crcLength = Read16(fid + 10);
    if (length < 40 || length > available ||
        crcLength < raw - 16 || crcLength > length - 16)
        return 0;
    for (i = 0; i < 16; ++i)
        if (i != 4) checksum += fid[i];
    if ((uint8_t)checksum != fid[4] ||
        TagCrc(fid + 16, crcLength) != Read16(fid + 8))
        return 0;
    *recordLength = length;
    return 1;
}

/* One complete directory FID changes from live to deleted.  A torn sector,
 * changed name or neighboring record is not an eligible recovery hint. */
static int
DirectoryFidPairLiveDeleted(
    const uint8_t main[UDFS_RECOVERY_SECTOR_SIZE],
    const uint8_t mirror[UDFS_RECOVERY_SECTOR_SIZE],
    uint32_t lbn, int *liveOnMirror, uint32_t *childLbn,
    uint32_t *recordOffset)
{
    uint32_t offset, matches = 0;
    for (offset = 0; offset <= UDFS_RECOVERY_SECTOR_SIZE - 40;
         offset += 4) {
        const uint8_t *a = main + offset, *b = mirror + offset;
        const uint8_t *live, *deleted;
        uint32_t aLength, bLength, j;
        int liveMirror;
        if (!ValidFidRecordInSector(a,
                 UDFS_RECOVERY_SECTOR_SIZE - offset, lbn, &aLength) ||
            !ValidFidRecordInSector(b,
                 UDFS_RECOVERY_SECTOR_SIZE - offset, lbn, &bLength) ||
            aLength != bLength)
            continue;
        if (!(a[18] & 4) && (b[18] & 4)) {
            live = a; deleted = b; liveMirror = 0;
        } else if ((a[18] & 4) && !(b[18] & 4)) {
            live = b; deleted = a; liveMirror = 1;
        } else continue;
        if (!(live[18] & 2) || (live[18] & 8) ||
            deleted[18] != (uint8_t)(live[18] | 4) ||
            (Read32(live + 20) >> 30) ||
            (Read32(live + 20) & 0x3fffffff) !=
                UDFS_RECOVERY_SECTOR_SIZE ||
            Read16(live + 28) != 1 ||
            !Read32(live + 24))
            continue;
        for (j = 20; j < 36; ++j)
            if (deleted[j]) break;
        if (j != 36) continue;
        for (j = 0; j < UDFS_RECOVERY_SECTOR_SIZE; ++j) {
            if (j >= offset && j < offset + aLength) {
                uint32_t local = j - offset;
                if (local == 4 || local == 8 || local == 9 ||
                    local == 18 || (local >= 20 && local < 36))
                    continue;
            }
            if (main[j] != mirror[j]) break;
        }
        if (j != UDFS_RECOVERY_SECTOR_SIZE || ++matches != 1)
            return 0;
        *liveOnMirror = liveMirror;
        *childLbn = Read32(live + 24);
        *recordOffset = offset;
    }
    return matches == 1;
}

static UDFS_RECOVERY_PROBE_STATUS
ReadFileExtents(const UDFS_RECOVERY_READER *reader,
                UDFS_RECOVERY_PROBE *result, uint32_t feLbn,
                uint8_t expectedType, RECOVERY_EXTENT_LIST *extents)
{
    uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE];
    uint32_t lba, attrLength, adLength, start, offset, mode;
    UDFS_RECOVERY_PROBE_STATUS status;

    if (feLbn >= result->PartitionBlocks)
        return UdfsRecoveryProbeCorrupt;
    lba = result->PartitionStart + feLbn;
    status = ReadSector(reader, result, lba, sector);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    status = ValidateTag(sector, 266, feLbn);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    mode = Read16(sector + 34) & 7;
    if (sector[27] != expectedType ||
        (mode != 0 && !(expectedType == 252 && mode == 3)))
        return UdfsRecoveryProbeUnsupported;

    memset(extents, 0, sizeof(*extents));
    extents->FileBytes = Read64(sector + 56);
    attrLength = Read32(sector + 208);
    adLength = Read32(sector + 212);
    if (attrLength > UDFS_RECOVERY_SECTOR_SIZE - 216 ||
        adLength > UDFS_RECOVERY_SECTOR_SIZE - 216 - attrLength ||
        (mode == 0 && (adLength & 7)))
        return UdfsRecoveryProbeCorrupt;
    start = 216 + attrLength;
    if (Read16(sector + 10) < start + adLength - 16)
        return UdfsRecoveryProbeCorrupt;

    /* An initially small metadata bitmap is an SBD embedded in its own EFE.
     * Keep the FE sector as the sole physical owner and map bitmap bytes to
     * its in-ICB payload. The EFE CRC must cover every payload byte. */
    if (mode == 3) {
        if (extents->FileBytes < 24 || extents->FileBytes != adLength ||
            start + extents->FileBytes > UDFS_RECOVERY_SECTOR_SIZE)
            return UdfsRecoveryProbeCorrupt;
        extents->Inline = 1;
        extents->InlineFeLbn = feLbn;
        extents->InlineOffset = start;
        return UdfsRecoveryProbeValidLayout;
    }

    for (offset = 0; offset < adLength; offset += 8) {
        uint32_t encoded = Read32(sector + start + offset);
        uint32_t bytes = encoded & 0x3fffffff;
        uint32_t blockLbn = Read32(sector + start + offset + 4);
        uint32_t blocks;
        if (!bytes) {
            if (encoded || blockLbn) return UdfsRecoveryProbeCorrupt;
            continue;
        }
        if (encoded >> 30 ||
            (expectedType != 252 &&
             (bytes & (UDFS_RECOVERY_SECTOR_SIZE - 1))))
            return UdfsRecoveryProbeUnsupported;
        blocks = (bytes + UDFS_RECOVERY_SECTOR_SIZE - 1) /
                 UDFS_RECOVERY_SECTOR_SIZE;
        if (!blocks || blockLbn >= result->PartitionBlocks ||
            blocks > result->PartitionBlocks - blockLbn ||
            extents->Count == UDFS_RECOVERY_MAX_EXTENTS ||
            blocks > UINT32_MAX - extents->TotalBlocks)
            return UdfsRecoveryProbeCorrupt;
        extents->Items[extents->Count].Lbn = blockLbn;
        extents->Items[extents->Count].Blocks = blocks;
        extents->Items[extents->Count].Bytes = bytes;
        extents->Items[extents->Count].Ref = 0;
        extents->Count++;
        extents->TotalBlocks += blocks;
    }
    if (!extents->Count ||
        (uint64_t)extents->TotalBlocks * UDFS_RECOVERY_SECTOR_SIZE <
            extents->FileBytes)
        return UdfsRecoveryProbeCorrupt;
    return UdfsRecoveryProbeValidLayout;
}

static int
RangesOverlap(const RECOVERY_EXTENT *left, const RECOVERY_EXTENT *right)
{
    return left->Lbn < right->Lbn + right->Blocks &&
           right->Lbn < left->Lbn + left->Blocks;
}

static UDFS_RECOVERY_PROBE_STATUS
MapExtentByte(const UDFS_RECOVERY_PROBE *result,
              const RECOVERY_EXTENT_LIST *extents, uint64_t offset,
              uint32_t *lba, uint32_t *sectorOffset)
{
    uint32_t i;
    if (offset >= extents->FileBytes) return UdfsRecoveryProbeCorrupt;
    if (extents->Inline) {
        if (extents->InlineFeLbn >= result->PartitionBlocks ||
            extents->InlineOffset >= UDFS_RECOVERY_SECTOR_SIZE ||
            offset >= UDFS_RECOVERY_SECTOR_SIZE - extents->InlineOffset)
            return UdfsRecoveryProbeCorrupt;
        *lba = result->PartitionStart + extents->InlineFeLbn;
        *sectorOffset = extents->InlineOffset + (uint32_t)offset;
        return UdfsRecoveryProbeValidLayout;
    }
    for (i = 0; i < extents->Count; ++i) {
        if (offset < extents->Items[i].Bytes) {
            *lba = result->PartitionStart + extents->Items[i].Lbn +
                   (uint32_t)(offset / UDFS_RECOVERY_SECTOR_SIZE);
            *sectorOffset = (uint32_t)(offset % UDFS_RECOVERY_SECTOR_SIZE);
            return UdfsRecoveryProbeValidLayout;
        }
        offset -= extents->Items[i].Bytes;
    }
    return UdfsRecoveryProbeCorrupt;
}

static UDFS_RECOVERY_PROBE_STATUS
ReadCachedByte(const UDFS_RECOVERY_READER *reader,
               UDFS_RECOVERY_PROBE *result, RECOVERY_SECTOR_CACHE *cache,
               uint32_t lba, uint32_t offset, uint8_t *value)
{
    UDFS_RECOVERY_PROBE_STATUS status;
    if (offset >= UDFS_RECOVERY_SECTOR_SIZE)
        return UdfsRecoveryProbeCorrupt;
    if (!cache->Valid || cache->Lba != lba) {
        status = ReadSector(reader, result, lba, cache->Data);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        cache->Lba = lba;
        cache->Valid = 1;
    }
    *value = cache->Data[offset];
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
MapMetadataBlock(const UDFS_RECOVERY_PROBE *result,
                 const RECOVERY_EXTENT_LIST *extents, uint32_t block,
                 uint32_t *lba)
{
    uint32_t i;
    if (block >= result->MetadataBlocks) return UdfsRecoveryProbeCorrupt;
    for (i = 0; i < extents->Count; ++i) {
        if (block < extents->Items[i].Blocks) {
            *lba = result->PartitionStart + extents->Items[i].Lbn + block;
            return UdfsRecoveryProbeValidLayout;
        }
        block -= extents->Items[i].Blocks;
    }
    return UdfsRecoveryProbeCorrupt;
}

typedef struct _RECOVERY_GRAPH_ENTRY {
    uint32_t Lbn;
    uint32_t Bytes;
    uint32_t ParentLbn;
    uint64_t StreamOwnerUniqueId;
    uint16_t Ref;
    uint16_t ParentRef;
    uint8_t Directory;
    /* 0: ordinary namespace, 1: EFE stream directory, 2: named stream. */
    uint8_t StreamRole;
} RECOVERY_GRAPH_ENTRY;

typedef struct _RECOVERY_NAME_SLOT {
    uint32_t Hash;
    uint32_t OffsetPlusOne;
} RECOVERY_NAME_SLOT;

/* Physical capacity must not require three dense nonpaged bitmaps. A page
 * with no Data is uniformly clear (SetBits == 0) or set (SetBits == its
 * valid bit count). Only mixed pages require a 4 KiB allocation. */
#define RECOVERY_BITMAP_PAGE_SHIFT 15U
#define RECOVERY_BITMAP_PAGE_BITS (1U << RECOVERY_BITMAP_PAGE_SHIFT)
#define RECOVERY_BITMAP_PAGE_BYTES (RECOVERY_BITMAP_PAGE_BITS / 8U)

typedef struct _RECOVERY_BITMAP_PAGE {
    uint8_t *Data;
    uint32_t SetBits;
} RECOVERY_BITMAP_PAGE;

typedef struct _RECOVERY_BITMAP {
    RECOVERY_BITMAP_PAGE *Pages;
    uint32_t BitCount;
    uint32_t PageCount;
} RECOVERY_BITMAP;

typedef struct _RECOVERY_GRAPH {
    const UDFS_RECOVERY_READER *Reader;
    UDFS_RECOVERY_PROBE *Result;
    const RECOVERY_EXTENT_LIST *Metadata;
    const RECOVERY_EXTENT_LIST *BitmapFile;
    RECOVERY_BITMAP PhysicalOwned;
    uint8_t *MetadataOwned;
    RECOVERY_BITMAP PhysicalVisited;
    uint8_t *MetadataVisited;
    RECOVERY_BITMAP PhysicalDirs;
    uint8_t *MetadataDirs;
    uint8_t *MetadataInlineFileFes;
    RECOVERY_GRAPH_ENTRY *Queue;
    RECOVERY_EXTENT_LIST *ScratchExtents;
    uint32_t QueueCount;
    uint32_t QueueCapacity;
    uint32_t FileReferences;
    uint64_t *UniqueIds;
    uint32_t UniqueIdCount;
    uint32_t UniqueIdCapacity;
    RECOVERY_SECTOR_CACHE PhysicalBitmapCache;
    RECOVERY_SECTOR_CACHE MetadataBitmapCache;
} RECOVERY_GRAPH;

static UDFS_RECOVERY_PROBE_STATUS
GraphMetadataBitIsFree(RECOVERY_GRAPH *graph, uint32_t lbn, int *freeBit)
{
    uint32_t lba, offset;
    uint8_t value;
    UDFS_RECOVERY_PROBE_STATUS status;
    if (lbn >= graph->Result->MetadataBlocks)
        return UdfsRecoveryProbeCorrupt;
    status = MapExtentByte(graph->Result, graph->BitmapFile,
                          24ULL + (lbn >> 3), &lba, &offset);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    status = ReadCachedByte(graph->Reader, graph->Result,
                            &graph->MetadataBitmapCache,
                            lba, offset, &value);
    if (status == UdfsRecoveryProbeValidLayout)
        *freeBit = (value >> (lbn & 7)) & 1;
    return status;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphRecordUniqueId(RECOVERY_GRAPH *graph, uint64_t id, int root)
{
    uint32_t slot, i, capacity;
    uint64_t *replacement;
    if (!id)
        return root ? UdfsRecoveryProbeValidLayout : UdfsRecoveryProbeCorrupt;
    if (root || (uint32_t)id < 16)
        return UdfsRecoveryProbeCorrupt;
    if (graph->UniqueIdCount * 2 >= graph->UniqueIdCapacity) {
        if (graph->UniqueIdCapacity >= 2 * 1024 * 1024)
            return UdfsRecoveryProbeUnsupported;
        capacity = graph->UniqueIdCapacity ? graph->UniqueIdCapacity * 2 : 1024;
        replacement = (uint64_t *)graph->Reader->Allocate(
            graph->Reader->Context, (size_t)capacity * sizeof(*replacement));
        if (!replacement) return UdfsRecoveryProbeNoMemory;
        memset(replacement, 0, (size_t)capacity * sizeof(*replacement));
        for (i = 0; i < graph->UniqueIdCapacity; ++i) {
            uint64_t old = graph->UniqueIds[i];
            if (!old) continue;
            slot = ((uint32_t)old ^ (uint32_t)(old >> 32)) * 2654435761U;
            slot &= capacity - 1;
            while (replacement[slot]) slot = (slot + 1) & (capacity - 1);
            replacement[slot] = old;
        }
        if (graph->UniqueIds)
            graph->Reader->Free(graph->Reader->Context, graph->UniqueIds);
        graph->UniqueIds = replacement;
        graph->UniqueIdCapacity = capacity;
    }
    slot = ((uint32_t)id ^ (uint32_t)(id >> 32)) * 2654435761U;
    slot &= graph->UniqueIdCapacity - 1;
    while (graph->UniqueIds[slot]) {
        if (graph->UniqueIds[slot] == id) return UdfsRecoveryProbeCorrupt;
        slot = (slot + 1) & (graph->UniqueIdCapacity - 1);
    }
    graph->UniqueIds[slot] = id;
    graph->UniqueIdCount++;
    return UdfsRecoveryProbeValidLayout;
}

/* The recovery namespace checker deliberately supports ASCII names only.
 * Ordinary clean mounts retain the full driver's Unicode/hard-link support.
 * Do not approximate an unknown Unicode collation during crash recovery. */
static UDFS_RECOVERY_PROBE_STATUS
RecoveryName(const uint8_t *fid, uint8_t name[255], uint32_t *length,
             uint32_t *hash)
{
    const uint8_t *encoded = fid + 38 + Read16(fid + 36);
    uint32_t i, step, bytes = fid[19];
    if (bytes < 2 || (encoded[0] != 8 && encoded[0] != 16))
        return UdfsRecoveryProbeCorrupt;
    step = encoded[0] == 16 ? 2 : 1;
    if ((bytes - 1) % step) return UdfsRecoveryProbeCorrupt;
    *length = 0;
    *hash = 2166136261U;
    for (i = 1; i < bytes; i += step) {
        uint32_t value = step == 2 ?
            ((uint32_t)encoded[i] << 8) | encoded[i + 1] : encoded[i];
        if (value > 127) return UdfsRecoveryProbeUnsupported;
        if (!value || value == '/' || value == '\\')
            return UdfsRecoveryProbeCorrupt;
        if (value >= 'a' && value <= 'z') value -= 'a' - 'A';
        name[(*length)++] = (uint8_t)value;
        *hash = (*hash ^ value) * 16777619U;
    }
    if ((*length == 1 && name[0] == '.') ||
        (*length == 2 && name[0] == '.' && name[1] == '.'))
        return UdfsRecoveryProbeCorrupt;
    return UdfsRecoveryProbeValidLayout;
}

static int
BitIsSet(const uint8_t *bits, uint32_t index)
{
    return (bits[index >> 3] >> (index & 7)) & 1;
}

static void
SetBit(uint8_t *bits, uint32_t index)
{
    bits[index >> 3] |= (uint8_t)(1U << (index & 7));
}

static uint32_t
CountByteBits(uint8_t value)
{
    uint32_t bits = value;
    bits -= (bits >> 1) & 0x55U;
    bits = (bits & 0x33U) + ((bits >> 2) & 0x33U);
    return (bits + (bits >> 4)) & 0x0fU;
}

static UDFS_RECOVERY_PROBE_STATUS
BitmapInitialize(const UDFS_RECOVERY_READER *reader,
                 RECOVERY_BITMAP *bitmap, uint32_t bitCount)
{
    size_t bytes;
    bitmap->BitCount = bitCount;
    bitmap->PageCount = (uint32_t)(((uint64_t)bitCount +
        RECOVERY_BITMAP_PAGE_BITS - 1) >> RECOVERY_BITMAP_PAGE_SHIFT);
    bytes = (size_t)bitmap->PageCount * sizeof(*bitmap->Pages);
    bitmap->Pages = (RECOVERY_BITMAP_PAGE *)reader->Allocate(
        reader->Context, bytes);
    if (!bitmap->Pages) return UdfsRecoveryProbeNoMemory;
    memset(bitmap->Pages, 0, bytes);
    return UdfsRecoveryProbeValidLayout;
}

static void
BitmapRelease(const UDFS_RECOVERY_READER *reader, RECOVERY_BITMAP *bitmap)
{
    uint32_t i;
    if (!bitmap->Pages) return;
    for (i = 0; i < bitmap->PageCount; ++i)
        if (bitmap->Pages[i].Data)
            reader->Free(reader->Context, bitmap->Pages[i].Data);
    reader->Free(reader->Context, bitmap->Pages);
    memset(bitmap, 0, sizeof(*bitmap));
}

static int
BitmapBitIsSet(const RECOVERY_BITMAP *bitmap, uint32_t index)
{
    const RECOVERY_BITMAP_PAGE *page =
        &bitmap->Pages[index >> RECOVERY_BITMAP_PAGE_SHIFT];
    return page->Data ? BitIsSet(page->Data,
        index & (RECOVERY_BITMAP_PAGE_BITS - 1)) : page->SetBits != 0;
}

/* Byte indices never straddle a sparse page. The caller masks the unused
 * high bits of the final byte, including a uniformly set final page. */
static uint8_t
BitmapReadByte(const RECOVERY_BITMAP *bitmap, uint32_t byteIndex)
{
    const RECOVERY_BITMAP_PAGE *page =
        &bitmap->Pages[byteIndex / RECOVERY_BITMAP_PAGE_BYTES];
    return page->Data ? page->Data[byteIndex % RECOVERY_BITMAP_PAGE_BYTES] :
           (page->SetBits ? 0xff : 0);
}

static uint32_t
FirstByteBit(uint8_t value)
{
    uint32_t bit = 0;
    /* Used only for a nonzero mismatch mask. */
    while (!(value & 1)) {
        value >>= 1;
        bit++;
    }
    return bit;
}

static UDFS_RECOVERY_PROBE_STATUS
BitmapSetRange(const UDFS_RECOVERY_READER *reader, RECOVERY_BITMAP *bitmap,
               uint32_t first, uint32_t count, uint32_t *alreadySet)
{
    *alreadySet = 0;
    if (first > bitmap->BitCount || count > bitmap->BitCount - first)
        return UdfsRecoveryProbeCorrupt;
    while (count) {
        uint32_t pageIndex = first >> RECOVERY_BITMAP_PAGE_SHIFT;
        uint32_t offset = first & (RECOVERY_BITMAP_PAGE_BITS - 1);
        uint32_t valid = bitmap->BitCount -
            (pageIndex << RECOVERY_BITMAP_PAGE_SHIFT);
        uint32_t take, i, remaining;
        RECOVERY_BITMAP_PAGE *page = &bitmap->Pages[pageIndex];
        if (valid > RECOVERY_BITMAP_PAGE_BITS)
            valid = RECOVERY_BITMAP_PAGE_BITS;
        take = valid - offset;
        if (take > count) take = count;
        if (!offset && take == valid) {
            *alreadySet += page->SetBits;
            if (page->Data) reader->Free(reader->Context, page->Data);
            page->Data = NULL;
            page->SetBits = valid;
        } else if (!page->Data && page->SetBits) {
            *alreadySet += take;
        } else {
            if (!page->Data) {
                page->Data = (uint8_t *)reader->Allocate(reader->Context,
                    RECOVERY_BITMAP_PAGE_BYTES);
                if (!page->Data) return UdfsRecoveryProbeNoMemory;
                memset(page->Data, 0, RECOVERY_BITMAP_PAGE_BYTES);
            }
            i = offset;
            remaining = take;
            while (remaining) {
                uint32_t width = 8 - (i & 7);
                uint32_t old;
                uint8_t mask;
                if (width > remaining) width = remaining;
                mask = (uint8_t)(((1U << width) - 1) << (i & 7));
                old = CountByteBits(page->Data[i >> 3] & mask);
                *alreadySet += old;
                page->SetBits += width - old;
                page->Data[i >> 3] |= mask;
                i += width;
                remaining -= width;
            }
            if (page->SetBits == valid) {
                reader->Free(reader->Context, page->Data);
                page->Data = NULL;
            }
        }
        first += take;
        count -= take;
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphOwn(RECOVERY_GRAPH *graph, uint16_t ref, uint32_t lbn,
         uint32_t bytes)
{
    uint32_t blocks, limit, i;
    uint8_t *owned;
    uint32_t *count;
    if (!bytes) return UdfsRecoveryProbeValidLayout;
    blocks = (bytes + UDFS_RECOVERY_SECTOR_SIZE - 1) /
             UDFS_RECOVERY_SECTOR_SIZE;
    if (ref == 0) {
        uint32_t overlap;
        UDFS_RECOVERY_PROBE_STATUS status;
        limit = graph->Result->PartitionBlocks;
        if (lbn >= limit || blocks > limit - lbn)
            return UdfsRecoveryProbeCorrupt;
        status = BitmapSetRange(graph->Reader, &graph->PhysicalOwned,
                                 lbn, blocks, &overlap);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (overlap > UINT32_MAX - graph->Result->OverlapBlocks)
            return UdfsRecoveryProbeCorrupt;
        graph->Result->OverlapBlocks += overlap;
        graph->Result->OwnedPhysicalBlocks += blocks - overlap;
        return UdfsRecoveryProbeValidLayout;
    } else if (ref == 1) {
        limit = graph->Result->MetadataBlocks;
        owned = graph->MetadataOwned;
        count = &graph->Result->OwnedMetadataBlocks;
    } else {
        return UdfsRecoveryProbeUnsupported;
    }
    if (lbn >= limit || blocks > limit - lbn)
        return UdfsRecoveryProbeCorrupt;
    for (i = 0; i < blocks; ++i) {
        if (BitIsSet(owned, lbn + i))
            graph->Result->OverlapBlocks++;
        else {
            SetBit(owned, lbn + i);
            ++*count;
        }
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphReadLogical(RECOVERY_GRAPH *graph, uint16_t ref,
                 uint32_t lbn, uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE])
{
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t physical;
    if (ref == 0) {
        if (lbn >= graph->Result->PartitionBlocks)
            return UdfsRecoveryProbeCorrupt;
        physical = graph->Result->PartitionStart + lbn;
    } else if (ref == 1) {
        status = MapMetadataBlock(graph->Result, graph->Metadata,
                                  lbn, &physical);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (graph->Result->FidSplitCount &&
            lbn == graph->Result->FidSplitLbn) {
            if (physical != graph->Result->FidSplitMainLba)
                return UdfsRecoveryProbeCorrupt;
            if (graph->Result->FidSplitLiveOnMirror)
                physical = graph->Result->FidSplitMirrorLba;
        }
    } else {
        return UdfsRecoveryProbeUnsupported;
    }
    return ReadSector(graph->Reader, graph->Result, physical, sector);
}

static UDFS_RECOVERY_PROBE_STATUS
GraphPush(RECOVERY_GRAPH *graph, uint16_t ref, uint32_t lbn,
          uint32_t bytes, int directory, uint16_t parentRef,
          uint32_t parentLbn, uint8_t streamRole,
          uint64_t streamOwnerUniqueId)
{
    RECOVERY_GRAPH_ENTRY *replacement;
    uint32_t capacity;
    if (graph->QueueCount == graph->QueueCapacity) {
        if (graph->QueueCapacity >= 1024 * 1024)
            return UdfsRecoveryProbeUnsupported;
        capacity = graph->QueueCapacity ? graph->QueueCapacity * 2 : 1024;
        replacement = (RECOVERY_GRAPH_ENTRY *)graph->Reader->Allocate(
            graph->Reader->Context, (size_t)capacity * sizeof(*replacement));
        if (!replacement) return UdfsRecoveryProbeNoMemory;
        if (graph->Queue) {
            memcpy(replacement, graph->Queue,
                   (size_t)graph->QueueCount * sizeof(*replacement));
            graph->Reader->Free(graph->Reader->Context, graph->Queue);
        }
        graph->Queue = replacement;
        graph->QueueCapacity = capacity;
    }
    graph->Queue[graph->QueueCount].Ref = ref;
    graph->Queue[graph->QueueCount].Lbn = lbn;
    graph->Queue[graph->QueueCount].Bytes = bytes;
    graph->Queue[graph->QueueCount].ParentRef = parentRef;
    graph->Queue[graph->QueueCount].ParentLbn = parentLbn;
    graph->Queue[graph->QueueCount].Directory = directory ? 1 : 0;
    graph->Queue[graph->QueueCount].StreamRole = streamRole;
    graph->Queue[graph->QueueCount].StreamOwnerUniqueId =
        streamOwnerUniqueId;
    graph->QueueCount++;
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphVisit(RECOVERY_GRAPH *graph, const RECOVERY_GRAPH_ENTRY *entry,
           int *alreadyVisited)
{
    uint8_t *visited = NULL, *directories = NULL;
    uint32_t limit;
    UDFS_RECOVERY_PROBE_STATUS status;
    if (entry->Ref == 0) {
        limit = graph->Result->PartitionBlocks;
    } else if (entry->Ref == 1) {
        visited = graph->MetadataVisited;
        directories = graph->MetadataDirs;
        limit = graph->Result->MetadataBlocks;
    } else return UdfsRecoveryProbeUnsupported;
    if (entry->Lbn >= limit || entry->Bytes != UDFS_RECOVERY_SECTOR_SIZE)
        return UdfsRecoveryProbeUnsupported;
    *alreadyVisited = entry->Ref == 0 ?
        BitmapBitIsSet(&graph->PhysicalVisited, entry->Lbn) :
        BitIsSet(visited, entry->Lbn);
    if (*alreadyVisited) {
        if (entry->StreamRole)
            return UdfsRecoveryProbeCorrupt;
        int isDirectory = entry->Ref == 0 ?
            BitmapBitIsSet(&graph->PhysicalDirs, entry->Lbn) :
            BitIsSet(directories, entry->Lbn);
        if (entry->Directory || isDirectory != entry->Directory)
            return UdfsRecoveryProbeCorrupt;
        return UdfsRecoveryProbeValidLayout;
    }
    if (entry->Ref == 0) {
        uint32_t overlap;
        status = BitmapSetRange(graph->Reader, &graph->PhysicalVisited,
                                 entry->Lbn, 1, &overlap);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (entry->Directory) {
            status = BitmapSetRange(graph->Reader, &graph->PhysicalDirs,
                                     entry->Lbn, 1, &overlap);
            if (status != UdfsRecoveryProbeValidLayout) return status;
        }
    } else {
        SetBit(visited, entry->Lbn);
        if (entry->Directory) SetBit(directories, entry->Lbn);
    }
    if (entry->Directory) {
        graph->Result->DirectoriesVisited++;
    } else if (!entry->StreamRole) {
        /* UDFS counts namespace files in LVID, but neither its stream
         * directory nor named stream FEs.  Both are still visited and owned
         * by the graph above. */
        graph->Result->FilesVisited++;
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphParseFileAds(RECOVERY_GRAPH *graph, const RECOVERY_GRAPH_ENTRY *file,
                  const uint8_t fe[UDFS_RECOVERY_SECTOR_SIZE],
                  RECOVERY_EXTENT_LIST *dataExtents, uint32_t *inlineStart,
                  uint32_t *inlineLength, uint32_t *modeOut)
{
    uint8_t source[UDFS_RECOVERY_SECTOR_SIZE];
    uint32_t mode = Read16(fe + 34) & 7;
    uint32_t attrOffset, adOffset, dataOffset;
    uint32_t start, length, sourceStart, sourceLength, seenCount = 0;
    uint32_t seenLbn[32];
    uint16_t seenRef[32];
    UDFS_RECOVERY_PROBE_STATUS status;
    uint64_t dataBytes = 0;

    if (Read16(fe) == 266) {
        attrOffset = 208; adOffset = 212; dataOffset = 216;
    } else if (Read16(fe) == 261) {
        attrOffset = 168; adOffset = 172; dataOffset = 176;
    } else return UdfsRecoveryProbeCorrupt;
    if (mode != 0 && mode != 1 && mode != 3)
        return UdfsRecoveryProbeUnsupported;
    if (Read32(fe + attrOffset) > UDFS_RECOVERY_SECTOR_SIZE - dataOffset)
        return UdfsRecoveryProbeCorrupt;
    start = dataOffset + Read32(fe + attrOffset);
    length = Read32(fe + adOffset);
    if (start > UDFS_RECOVERY_SECTOR_SIZE ||
        length > UDFS_RECOVERY_SECTOR_SIZE - start ||
        Read16(fe + 10) < start + length - 16)
        return UdfsRecoveryProbeCorrupt;
    *modeOut = mode;
    *inlineStart = start;
    *inlineLength = length;
    memset(dataExtents, 0, sizeof(*dataExtents));
    dataExtents->FileBytes = Read64(fe + 56);
    if (mode == 3)
        return dataExtents->FileBytes <= length ?
            UdfsRecoveryProbeValidLayout : UdfsRecoveryProbeCorrupt;

    memcpy(source, fe, sizeof(source));
    sourceStart = start;
    sourceLength = length;
    for (;;) {
        uint32_t offset, step = mode == 0 ? 8 : 16;
        uint32_t nextLbn = 0, nextBytes = 0;
        uint16_t nextRef = 0;
        int haveNext = 0;
        if (sourceLength % step ||
            sourceStart > UDFS_RECOVERY_SECTOR_SIZE ||
            sourceLength > UDFS_RECOVERY_SECTOR_SIZE - sourceStart ||
            Read16(source + 10) < sourceStart + sourceLength - 16)
            return UdfsRecoveryProbeCorrupt;
        for (offset = sourceStart; offset < sourceStart + sourceLength;
             offset += step) {
            uint32_t encoded = Read32(source + offset);
            uint32_t bytes = encoded & 0x3fffffff;
            uint32_t kind = encoded >> 30;
            uint32_t lbn = Read32(source + offset + 4);
            uint16_t ref = mode == 0 ? file->Ref :
                           Read16(source + offset + 8);
            if (!bytes) continue;
            if (kind == 3) {
                if (haveNext || bytes < UDFS_RECOVERY_SECTOR_SIZE)
                    return UdfsRecoveryProbeUnsupported;
                nextLbn = lbn;
                nextRef = ref;
                nextBytes = bytes;
                haveNext = 1;
            } else if (kind == 0 || kind == 1) {
                RECOVERY_EXTENT *extent;
                if (haveNext || dataExtents->Count == UDFS_RECOVERY_MAX_EXTENTS)
                    return UdfsRecoveryProbeUnsupported;
                /* An allocated but unrecorded AD owns its blocks.  It is
                 * valid in an ordinary file, but cannot supply FID bytes. */
                if (kind == 1 &&
                    (file->Directory || file->StreamRole == 1 ||
                     (bytes & (UDFS_RECOVERY_SECTOR_SIZE - 1))))
                    return UdfsRecoveryProbeUnsupported;
                status = GraphOwn(graph, ref, lbn, bytes);
                if (status != UdfsRecoveryProbeValidLayout) return status;
                extent = &dataExtents->Items[dataExtents->Count++];
                extent->Ref = ref;
                extent->Lbn = lbn;
                extent->Bytes = bytes;
                extent->Blocks = (bytes + UDFS_RECOVERY_SECTOR_SIZE - 1) /
                                 UDFS_RECOVERY_SECTOR_SIZE;
                dataBytes += bytes;
            } else {
                return UdfsRecoveryProbeUnsupported;
            }
        }
        if (!haveNext) break;
        if (seenCount == 32 || nextBytes != UDFS_RECOVERY_SECTOR_SIZE)
            return UdfsRecoveryProbeUnsupported;
        for (offset = 0; offset < seenCount; ++offset)
            if (seenLbn[offset] == nextLbn && seenRef[offset] == nextRef)
                return UdfsRecoveryProbeCorrupt;
        seenLbn[seenCount] = nextLbn;
        seenRef[seenCount++] = nextRef;
        status = GraphOwn(graph, nextRef, nextLbn, nextBytes);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        status = GraphReadLogical(graph, nextRef, nextLbn, source);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        status = ValidateTag(source, 258, nextLbn);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        sourceStart = 24;
        sourceLength = Read32(source + 20);
    }
    return dataBytes >= dataExtents->FileBytes ?
        UdfsRecoveryProbeValidLayout : UdfsRecoveryProbeCorrupt;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphReadDirectory(RECOVERY_GRAPH *graph,
                   const RECOVERY_GRAPH_ENTRY *file,
                   const uint8_t fe[UDFS_RECOVERY_SECTOR_SIZE],
                   const RECOVERY_EXTENT_LIST *extents,
                   uint32_t inlineStart, uint32_t mode,
                   uint8_t **directory, uint32_t *length)
{
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t copied = 0, i;
    if (!extents->FileBytes || extents->FileBytes > 16 * 1024 * 1024)
        return UdfsRecoveryProbeUnsupported;
    *length = (uint32_t)extents->FileBytes;
    *directory = (uint8_t *)graph->Reader->Allocate(graph->Reader->Context,
                                                     *length);
    if (!*directory) return UdfsRecoveryProbeNoMemory;
    if (mode == 3) {
        memcpy(*directory, fe + inlineStart, *length);
        return UdfsRecoveryProbeValidLayout;
    }
    for (i = 0; i < extents->Count && copied < *length; ++i) {
        const RECOVERY_EXTENT *extent = &extents->Items[i];
        uint32_t byteOffset;
        for (byteOffset = 0; byteOffset < extent->Bytes && copied < *length;
             byteOffset += UDFS_RECOVERY_SECTOR_SIZE) {
            uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE];
            uint32_t available = extent->Bytes - byteOffset;
            uint32_t take = *length - copied;
            if (take > available) take = available;
            if (take > UDFS_RECOVERY_SECTOR_SIZE)
                take = UDFS_RECOVERY_SECTOR_SIZE;
            status = GraphReadLogical(graph, extent->Ref,
                        extent->Lbn + byteOffset / UDFS_RECOVERY_SECTOR_SIZE,
                        sector);
            if (status != UdfsRecoveryProbeValidLayout) return status;
            memcpy(*directory + copied, sector, take);
            copied += take;
        }
    }
    (void)file;
    return copied == *length ? UdfsRecoveryProbeValidLayout :
           UdfsRecoveryProbeCorrupt;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphScanFids(RECOVERY_GRAPH *graph,
              const RECOVERY_GRAPH_ENTRY *directoryFile,
              const RECOVERY_EXTENT_LIST *extents, uint32_t mode,
              const uint8_t *directory, uint32_t length, uint16_t links,
              RECOVERY_NAME_SLOT *names, uint32_t nameCapacity)
{
    uint32_t offset = 0, parents = 0, subdirectories = 0;
    while (offset < length) {
        const uint8_t *fid = directory + offset;
        uint32_t rawLength, recordLength, crcLength, expectedLbn;
        uint32_t recordSectorOffset = UINT32_MAX;
        uint32_t checksum = 0, i;
        uint8_t attributes;
        UDFS_RECOVERY_PROBE_STATUS status;
        if (length - offset < 38) return UdfsRecoveryProbeCorrupt;
        rawLength = 38 + Read16(fid + 36) + fid[19];
        recordLength = (rawLength + 3) & ~3U;
        crcLength = Read16(fid + 10);
        attributes = fid[18];
        if (recordLength > length - offset ||
            Read16(fid) != 257 ||
            (Read16(fid + 2) != 2 && Read16(fid + 2) != 3) ||
            Read16(fid + 16) != 1 || (attributes & ~0x1fU) ||
            crcLength < rawLength - 16 ||
            crcLength > recordLength - 16)
            return UdfsRecoveryProbeCorrupt;
        for (i = 0; i < 16; ++i)
            if (i != 4) checksum += fid[i];
        if ((uint8_t)checksum != fid[4] ||
            TagCrc(fid + 16, crcLength) != Read16(fid + 8))
            return UdfsRecoveryProbeCorrupt;
        if (mode == 3) {
            expectedLbn = directoryFile->Lbn;
        } else {
            uint32_t remaining = offset;
            for (i = 0; i < extents->Count; ++i) {
                if (remaining < extents->Items[i].Bytes) break;
                remaining -= extents->Items[i].Bytes;
            }
            if (i == extents->Count) return UdfsRecoveryProbeCorrupt;
            expectedLbn = extents->Items[i].Lbn +
                          remaining / UDFS_RECOVERY_SECTOR_SIZE;
            recordSectorOffset =
                remaining % UDFS_RECOVERY_SECTOR_SIZE;
        }
        if (Read32(fid + 12) != expectedLbn)
            return UdfsRecoveryProbeCorrupt;
        if (graph->Result->FidSplitCount &&
            expectedLbn == graph->Result->FidSplitLbn &&
            recordSectorOffset ==
                graph->Result->FidSplitRecordOffset) {
            if (graph->Result->FidSplitSeen ||
                !(attributes & 2) || (attributes & (4 | 8)) ||
                Read16(fid + 28) != 1 ||
                Read32(fid + 24) !=
                    graph->Result->FidSplitChildLbn)
                return UdfsRecoveryProbeCorrupt;
            graph->Result->FidSplitSeen = 1;
            graph->Result->FidSplitParentLbn =
                directoryFile->Lbn;
        }
        graph->Result->FidsChecked++;
        if (!(attributes & 4) && (attributes & 8)) {
            if (++parents != 1 || fid[19] ||
                ((attributes & 2) != 0) ==
                    (directoryFile->StreamRole == 1) ||
                Read32(fid + 20) != UDFS_RECOVERY_SECTOR_SIZE ||
                Read32(fid + 24) != directoryFile->ParentLbn ||
                Read16(fid + 28) != directoryFile->ParentRef)
                return UdfsRecoveryProbeCorrupt;
        }
        if (!(attributes & (4 | 8))) {
            uint32_t encoded = Read32(fid + 20);
            uint32_t icbBytes = encoded & 0x3fffffff;
            uint32_t nameLength, hash, slot;
            uint8_t name[255];
            if (encoded >> 30 || !fid[19] ||
                (fid[38 + Read16(fid + 36)] != 8 &&
                 fid[38 + Read16(fid + 36)] != 16))
                return UdfsRecoveryProbeCorrupt;
            status = RecoveryName(fid, name, &nameLength, &hash);
            if (status != UdfsRecoveryProbeValidLayout) return status;
            slot = hash & (nameCapacity - 1);
            while (names[slot].OffsetPlusOne) {
                if (names[slot].Hash == hash) {
                    uint8_t other[255];
                    uint32_t otherLength, otherHash;
                    const uint8_t *previous = directory + names[slot].OffsetPlusOne - 1;
                    status = RecoveryName(previous, other, &otherLength, &otherHash);
                    if (status != UdfsRecoveryProbeValidLayout) return status;
                    if (nameLength == otherLength &&
                        !RecoveryDifference(name, other, nameLength))
                        return UdfsRecoveryProbeCorrupt;
                }
                slot = (slot + 1) & (nameCapacity - 1);
            }
            names[slot].Hash = hash;
            names[slot].OffsetPlusOne = offset + 1;
            if (directoryFile->StreamRole == 1 && (attributes & 2))
                return UdfsRecoveryProbeUnsupported;
            if (attributes & 2) subdirectories++;
            else if (directoryFile->StreamRole != 1)
                graph->FileReferences++;
            status = GraphPush(graph, Read16(fid + 28),
                                Read32(fid + 24), icbBytes,
                                (attributes & 2) != 0,
                                directoryFile->Ref, directoryFile->Lbn,
                                directoryFile->StreamRole == 1 ? 2 : 0,
                                directoryFile->StreamOwnerUniqueId);
            if (status != UdfsRecoveryProbeValidLayout) return status;
        }
        offset += recordLength;
    }
    if (offset != length || parents != 1)
        return UdfsRecoveryProbeCorrupt;
    /* Stream objects are owned by the graph but omitted from UDFS's LVID
     * file count.  The stream directory's parent points to the base FE. */
    if (directoryFile->StreamRole == 1)
        return subdirectories || links ? UdfsRecoveryProbeCorrupt :
               UdfsRecoveryProbeValidLayout;
    if (graph->Result->MirrorDirectorySplitCount &&
        directoryFile->Ref == 1 &&
        directoryFile->Lbn ==
            graph->Result->MirrorDirectoryLbn) {
        uint32_t expected = subdirectories + 1;
        if (graph->Result->DirectoryLinkFixCount ||
            graph->Result->MirrorDirectoryMainLinks != links ||
            (expected != links &&
             expected !=
                graph->Result->MirrorDirectoryMirrorLinks))
            return UdfsRecoveryProbeCorrupt;
        graph->Result->DirectoryLinkFixCount = 1;
        graph->Result->DirectoryLinkFixParentRef = directoryFile->Ref;
        graph->Result->DirectoryLinkFixParentLbn = directoryFile->Lbn;
        graph->Result->DirectoryLinkFixChildLbn = UINT32_MAX;
        graph->Result->DirectoryLinkFixStored = links;
        graph->Result->DirectoryLinkFixExpected = (uint16_t)expected;
        return UdfsRecoveryProbeValidLayout;
    }
    if (subdirectories + 1 == links)
        return UdfsRecoveryProbeValidLayout;
    /* Only the pre-FID side of one empty-directory deletion can have a
     * parent count one low.  Its still-reachable child FE must already be
     * pre-freed on disk.  All other count mismatches remain corruption. */
    if (subdirectories + 1 != (uint32_t)links + 1 ||
        graph->Result->DirectoryLinkFixCount ||
        directoryFile->Ref != 1)
        return UdfsRecoveryProbeCorrupt;
    {
        uint32_t child = UINT32_MAX, count = 0, cursor = 0;
        while (cursor < length) {
            const uint8_t *fid = directory + cursor;
            uint32_t size = (38 + Read16(fid + 36) + fid[19] + 3) & ~3U;
            if (!(fid[18] & (4 | 8)) && (fid[18] & 2)) {
                int freeBit = 0;
                UDFS_RECOVERY_PROBE_STATUS status;
                if (Read16(fid + 28) != 1)
                    return UdfsRecoveryProbeUnsupported;
                status = GraphMetadataBitIsFree(graph, Read32(fid + 24),
                                                &freeBit);
                if (status != UdfsRecoveryProbeValidLayout)
                    return status;
                if (freeBit) {
                    if (++count > 1)
                        return UdfsRecoveryProbeCorrupt;
                    child = Read32(fid + 24);
                }
            }
            cursor += size;
        }
        if (count != 1)
            return UdfsRecoveryProbeCorrupt;
        graph->Result->DirectoryLinkFixCount = 1;
        graph->Result->DirectoryLinkFixParentRef = directoryFile->Ref;
        graph->Result->DirectoryLinkFixParentLbn = directoryFile->Lbn;
        graph->Result->DirectoryLinkFixChildLbn = child;
        graph->Result->DirectoryLinkFixStored = links;
        graph->Result->DirectoryLinkFixExpected = (uint16_t)(subdirectories + 1);
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphProcessFile(RECOVERY_GRAPH *graph, const RECOVERY_GRAPH_ENTRY *file)
{
    uint8_t fe[UDFS_RECOVERY_SECTOR_SIZE];
    RECOVERY_EXTENT_LIST *dataExtents = graph->ScratchExtents;
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t inlineStart = 0, inlineLength = 0, mode = 0, dirLength = 0;
    uint16_t kind;
    uint16_t links, flags;
    uint32_t streamIcbBytes = 0;
    uint64_t uniqueId;
    uint8_t *directory = NULL;
    RECOVERY_NAME_SLOT *names = NULL;
    int alreadyVisited;

    status = GraphVisit(graph, file, &alreadyVisited);
    if (status != UdfsRecoveryProbeValidLayout || alreadyVisited)
        return status;
    status = GraphReadLogical(graph, file->Ref, file->Lbn, fe);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    kind = Read16(fe);
    if (kind != 261 && kind != 266)
        return UdfsRecoveryProbeCorrupt;
    status = ValidateTag(fe, kind, file->Lbn);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (fe[27] != (file->StreamRole == 1 ? 13 :
                   (file->Directory ? 4 : 5)))
        return UdfsRecoveryProbeCorrupt;
    flags = Read16(fe + 34);
    links = Read16(fe + 48);
    if (kind == 266) streamIcbBytes = Read32(fe + 152);
    if (file->StreamRole == 1) {
        if (links || streamIcbBytes || (flags & 0x2000))
            return UdfsRecoveryProbeCorrupt;
    } else if (file->StreamRole == 2) {
        if (links != 1 || streamIcbBytes || !(flags & 0x2000))
            return UdfsRecoveryProbeCorrupt;
    } else {
        if (!links || (flags & 0x2000))
            return UdfsRecoveryProbeCorrupt;
        if (streamIcbBytes) {
            if (file->Directory || kind != 266 ||
                streamIcbBytes != UDFS_RECOVERY_SECTOR_SIZE || links != 2)
                return UdfsRecoveryProbeUnsupported;
        } else if (!file->Directory && links != 1) {
            /* Ordinary hard links still require per-link accounting. */
            return UdfsRecoveryProbeUnsupported;
        }
    }
    uniqueId = Read64(fe + (kind == 266 ? 200 : 160));
    if (file->StreamRole) {
        /* UDFS stores the base FE's ID in its stream directory and all its
         * named streams.  Reject unbound or mismatched references. */
        if (!file->StreamOwnerUniqueId ||
            uniqueId != file->StreamOwnerUniqueId)
            return UdfsRecoveryProbeCorrupt;
    } else {
        status = GraphRecordUniqueId(graph, uniqueId, file->Directory &&
            file->Ref == file->ParentRef && file->Lbn == file->ParentLbn);
        if (status != UdfsRecoveryProbeValidLayout) return status;
    }
    if (uniqueId > graph->Result->MaxUniqueId)
        graph->Result->MaxUniqueId = uniqueId;
    status = GraphOwn(graph, file->Ref, file->Lbn, file->Bytes);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    status = GraphParseFileAds(graph, file, fe, dataExtents,
                               &inlineStart, &inlineLength, &mode);
    if (status != UdfsRecoveryProbeValidLayout)
        return status;
    if (streamIcbBytes) {
        status = GraphPush(graph, Read16(fe + 160), Read32(fe + 156),
                           streamIcbBytes, 0, file->Ref, file->Lbn,
                           1, uniqueId);
        if (status != UdfsRecoveryProbeValidLayout) return status;
    }
    if (file->Directory && graph->Result->DirectoryLinkFixCount &&
        file->Ref == 1 &&
        file->Lbn == graph->Result->DirectoryLinkFixChildLbn) {
        if (file->ParentRef !=
                graph->Result->DirectoryLinkFixParentRef ||
            file->ParentLbn !=
                graph->Result->DirectoryLinkFixParentLbn ||
            mode != 3 || dataExtents->FileBytes != 40 ||
            Read16(fe + 48) != 1)
            return UdfsRecoveryProbeCorrupt;
        graph->Result->DirectoryLinkFixChildVerified = 1;
    }
    if (!file->Directory && file->Ref == 1 && mode == 3)
        SetBit(graph->MetadataInlineFileFes, file->Lbn);
    if (!file->Directory && file->StreamRole != 1)
        return status;
    status = GraphReadDirectory(graph, file, fe, dataExtents,
                                inlineStart, mode, &directory, &dirLength);
    if (status == UdfsRecoveryProbeValidLayout) {
        uint32_t capacity = 1;
        while (capacity < 2 * (dirLength / 40 + 1)) capacity <<= 1;
        names = (RECOVERY_NAME_SLOT *)graph->Reader->Allocate(
            graph->Reader->Context, (size_t)capacity * sizeof(*names));
        if (!names) status = UdfsRecoveryProbeNoMemory;
        else {
            memset(names, 0, (size_t)capacity * sizeof(*names));
            status = GraphScanFids(graph, file, dataExtents, mode,
                                   directory, dirLength, Read16(fe + 48),
                                   names, capacity);
        }
    }
    if (names)
        graph->Reader->Free(graph->Reader->Context, names);
    if (directory)
        graph->Reader->Free(graph->Reader->Context, directory);
    return status;
}

/* Collect only free-to-owned bitmap transitions justified by the complete
 * namespace walk. The heap-allocated plan bounds distinct sectors, so a batch
 * of creates need not fit a guessed one-file crash pattern. */
static UDFS_RECOVERY_PROBE_STATUS
PlanOwnedMetadataBlock(const UDFS_RECOVERY_READER *reader,
                       UDFS_RECOVERY_PROBE *result,
                       const RECOVERY_EXTENT_LIST *bitmapFile,
                       UDFS_RECOVERY_REPAIR_PLAN *plan, uint32_t lbn)
{
    uint32_t lba, offset, i;
    uint8_t mask = (uint8_t)(1U << (lbn & 7));
    UDFS_RECOVERY_SECTOR_EDIT *edit;
    UDFS_RECOVERY_PROBE_STATUS status;

    status = MapExtentByte(result, bitmapFile, 24ULL + (lbn >> 3),
                            &lba, &offset);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    for (i = 0; i < plan->BitmapEditCount; ++i)
        if (plan->BitmapEdits[i].Lba == lba) break;
    if (i == plan->BitmapEditCount) {
        if (i == UDFS_RECOVERY_MAX_BITMAP_EDITS)
            return UdfsRecoveryProbeUnsupported;
        edit = &plan->BitmapEdits[i];
        edit->Lba = lba;
        status = ReadSector(reader, result, lba, edit->Before);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        memcpy(edit->After, edit->Before, UDFS_RECOVERY_SECTOR_SIZE);
        plan->BitmapEditCount++;
    }
    edit = &plan->BitmapEdits[i];
    if (!(edit->After[offset] & mask)) return UdfsRecoveryProbeCorrupt;
    edit->After[offset] &= (uint8_t)~mask;
    /* Some valid small SBDs cover bitmap bytes in their descriptor CRC.
     * Preserve that coverage instead of assuming the usual eight-byte CRC. */
    {
        uint32_t headerLba, headerOffset;
        status = MapExtentByte(result, bitmapFile, 0, &headerLba, &headerOffset);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (lba == headerLba) {
            uint8_t *tag = edit->After + headerOffset;
            uint32_t length = Read16(tag + 10), sum = 0, j;
            uint16_t crc;
            if ((!bitmapFile->Inline && headerOffset) ||
                headerOffset > UDFS_RECOVERY_SECTOR_SIZE - 24 ||
                (bitmapFile->Inline && bitmapFile->FileBytes >
                    UDFS_RECOVERY_SECTOR_SIZE - headerOffset) ||
                length > (bitmapFile->Inline ?
                    bitmapFile->FileBytes - 16 :
                    UDFS_RECOVERY_SECTOR_SIZE - 16))
                return UdfsRecoveryProbeCorrupt;
            crc = TagCrc(tag + 16, length);
            tag[8] = (uint8_t)crc;
            tag[9] = (uint8_t)(crc >> 8);
            for (j = 0; j < 16; ++j)
                if (j != 4) sum += tag[j];
            tag[4] = (uint8_t)sum;
            if (bitmapFile->Inline) {
                /* The embedded SBD lives inside an EFE. Its metadata bits
                 * are covered by the enclosing EFE descriptor CRC even when
                 * the SBD itself covers only its eight-byte size header. */
                length = Read16(edit->After + 10);
                if (length > UDFS_RECOVERY_SECTOR_SIZE - 16 ||
                    length < headerOffset + bitmapFile->FileBytes - 16)
                    return UdfsRecoveryProbeCorrupt;
                crc = TagCrc(edit->After + 16, length);
                edit->After[8] = (uint8_t)crc;
                edit->After[9] = (uint8_t)(crc >> 8);
                sum = 0;
                for (j = 0; j < 16; ++j)
                    if (j != 4) sum += edit->After[j];
                edit->After[4] = (uint8_t)sum;
                status = ValidateTag(edit->After, 266,
                                     bitmapFile->InlineFeLbn);
                if (status != UdfsRecoveryProbeValidLayout)
                    return status;
            }
        }
    }
    return UdfsRecoveryProbeValidLayout;
}

/* The namespace walk proves ownership of this physical block. Keep the same
 * sector-bounded plan as metadata repairs; an allocated but unreferenced
 * block is never accepted here. */
static UDFS_RECOVERY_PROBE_STATUS
PlanOwnedPhysicalBlock(const UDFS_RECOVERY_READER *reader,
                       UDFS_RECOVERY_PROBE *result,
                       UDFS_RECOVERY_REPAIR_PLAN *plan, uint32_t lbn)
{
    uint64_t byteOffset = 24ULL + (lbn >> 3);
    uint64_t address = (uint64_t)result->PartitionStart +
                       result->PhysicalBitmapLbn +
                       byteOffset / UDFS_RECOVERY_SECTOR_SIZE;
    uint32_t lba, offset, i;
    uint8_t mask = (uint8_t)(1U << (lbn & 7));
    UDFS_RECOVERY_SECTOR_EDIT *edit;
    UDFS_RECOVERY_PROBE_STATUS status;

    if (address >= reader->SectorCount) return UdfsRecoveryProbeCorrupt;
    lba = (uint32_t)address;
    offset = (uint32_t)(byteOffset % UDFS_RECOVERY_SECTOR_SIZE);
    for (i = 0; i < plan->BitmapEditCount; ++i)
        if (plan->BitmapEdits[i].Lba == lba) break;
    if (i == plan->BitmapEditCount) {
        if (i == UDFS_RECOVERY_MAX_BITMAP_EDITS)
            return UdfsRecoveryProbeUnsupported;
        edit = &plan->BitmapEdits[i];
        edit->Lba = lba;
        status = ReadSector(reader, result, lba, edit->Before);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        memcpy(edit->After, edit->Before, UDFS_RECOVERY_SECTOR_SIZE);
        plan->BitmapEditCount++;
    }
    edit = &plan->BitmapEdits[i];
    if (!(edit->After[offset] & mask)) return UdfsRecoveryProbeCorrupt;
    edit->After[offset] &= (uint8_t)~mask;
    if (lba == result->PartitionStart + result->PhysicalBitmapLbn) {
        uint32_t length = Read16(edit->After + 10), sum = 0, j;
        uint16_t crc;
        if (length > UDFS_RECOVERY_SECTOR_SIZE - 16)
            return UdfsRecoveryProbeCorrupt;
        crc = TagCrc(edit->After + 16, length);
        edit->After[8] = (uint8_t)crc;
        edit->After[9] = (uint8_t)(crc >> 8);
        for (j = 0; j < 16; ++j)
            if (j != 4) sum += edit->After[j];
        edit->After[4] = (uint8_t)sum;
    }
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
PlanParentLinkCount(const UDFS_RECOVERY_READER *reader,
                    UDFS_RECOVERY_PROBE *result,
                    const RECOVERY_EXTENT_LIST *mainFile,
                    const RECOVERY_EXTENT_LIST *mirrorFile,
                    UDFS_RECOVERY_REPAIR_PLAN *plan)
{
    uint32_t lba[2], i;
    UDFS_RECOVERY_PROBE_STATUS status;
    if (!result->MetadataDuplicated ||
        result->DirectoryLinkFixParentRef != 1 ||
        result->DirectoryLinkFixCount != 1 ||
        plan->FeEditCount)
        return UdfsRecoveryProbeCorrupt;
    status = MapMetadataBlock(result, mainFile,
                 result->DirectoryLinkFixParentLbn, &lba[0]);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    status = MapMetadataBlock(result, mirrorFile,
                 result->DirectoryLinkFixParentLbn, &lba[1]);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (lba[0] == lba[1]) return UdfsRecoveryProbeCorrupt;
    for (i = 0; i < 2; ++i) {
        UDFS_RECOVERY_SECTOR_EDIT *edit = &plan->FeEdits[i];
        uint16_t kind, crcLength, crc;
        uint32_t checksum = 0, j;
        edit->Lba = lba[i];
        status = ReadSector(reader, result, edit->Lba, edit->Before);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        kind = Read16(edit->Before);
        if ((kind != 261 && kind != 266) ||
            edit->Before[27] != 4 ||
            (i == 0 && Read16(edit->Before + 48) !=
                result->DirectoryLinkFixStored) ||
            (result->MirrorDirectorySplitCount &&
             Read16(edit->Before + 48) !=
                (i == 0 ? result->MirrorDirectoryMainLinks :
                          result->MirrorDirectoryMirrorLinks)))
            return UdfsRecoveryProbeCorrupt;
        status = ValidateTag(edit->Before, kind,
                             result->DirectoryLinkFixParentLbn);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        crcLength = Read16(edit->Before + 10);
        if (crcLength < 50 - 16 ||
            crcLength > UDFS_RECOVERY_SECTOR_SIZE - 16)
            return UdfsRecoveryProbeCorrupt;
        memcpy(edit->After, edit->Before, UDFS_RECOVERY_SECTOR_SIZE);
        Write16(edit->After + 48,
                result->DirectoryLinkFixExpected);
        crc = TagCrc(edit->After + 16, crcLength);
        Write16(edit->After + 8, crc);
        edit->After[4] = 0;
        for (j = 0; j < 16; ++j)
            if (j != 4) checksum += edit->After[j];
        edit->After[4] = (uint8_t)checksum;
        status = ValidateTag(edit->After, kind,
                             result->DirectoryLinkFixParentLbn);
        if (status != UdfsRecoveryProbeValidLayout) return status;
    }
    if (result->MirrorDirectorySplitCount) {
        if (result->MirrorDirectoryLbn !=
                result->DirectoryLinkFixParentLbn ||
            !DirectoryFePairDiffersOnlyInLinkCount(
                plan->FeEdits[0].Before,
                plan->FeEdits[1].Before,
                result->DirectoryLinkFixParentLbn))
            return UdfsRecoveryProbeCorrupt;
    } else if (RecoveryDifference(plan->FeEdits[0].Before,
                                  plan->FeEdits[1].Before,
                                  UDFS_RECOVERY_SECTOR_SIZE) != 0)
        return UdfsRecoveryProbeCorrupt;
    if (Read16(plan->FeEdits[0].Before + 48) !=
            result->DirectoryLinkFixExpected &&
        Read16(plan->FeEdits[1].Before + 48) !=
            result->DirectoryLinkFixExpected &&
        result->MirrorDirectorySplitCount)
        return UdfsRecoveryProbeCorrupt;
    if (RecoveryDifference(plan->FeEdits[0].Before,
                           plan->FeEdits[0].After,
                           UDFS_RECOVERY_SECTOR_SIZE) != 0) {
        plan->FeEditCount = 1;
    }
    if (RecoveryDifference(plan->FeEdits[1].Before,
                           plan->FeEdits[1].After,
                           UDFS_RECOVERY_SECTOR_SIZE) != 0) {
        if (plan->FeEditCount)
            plan->FeEditCount = 2;
        else {
            plan->FeEdits[0] = plan->FeEdits[1];
            plan->FeEditCount = 1;
        }
    }
    if (!plan->FeEditCount)
        return UdfsRecoveryProbeCorrupt;
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
PlanLiveFidCopy(const UDFS_RECOVERY_READER *reader,
                UDFS_RECOVERY_PROBE *result,
                UDFS_RECOVERY_REPAIR_PLAN *plan)
{
    uint8_t main[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t mirror[UDFS_RECOVERY_SECTOR_SIZE];
    const uint8_t *live, *deleted;
    int liveOnMirror;
    uint32_t child, offset;
    UDFS_RECOVERY_PROBE_STATUS status;
    if (result->FidSplitCount != 1 ||
        result->MirrorDirectorySplitCount ||
        !result->FidSplitSeen || plan->FidEditCount)
        return UdfsRecoveryProbeCorrupt;
    status = ReadSector(reader, result, result->FidSplitMainLba, main);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    status = ReadSector(reader, result, result->FidSplitMirrorLba,
                        mirror);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (!DirectoryFidPairLiveDeleted(main, mirror,
            result->FidSplitLbn, &liveOnMirror, &child, &offset) ||
        (uint8_t)liveOnMirror != result->FidSplitLiveOnMirror ||
        child != result->FidSplitChildLbn ||
        offset != result->FidSplitRecordOffset)
        return UdfsRecoveryProbeCorrupt;
    live = liveOnMirror ? mirror : main;
    deleted = liveOnMirror ? main : mirror;
    plan->FidEdit.Lba = liveOnMirror ?
        result->FidSplitMainLba : result->FidSplitMirrorLba;
    plan->FidLiveLba = liveOnMirror ?
        result->FidSplitMirrorLba : result->FidSplitMainLba;
    plan->FidEditLogicalLbn = result->FidSplitLbn;
    memcpy(plan->FidEdit.Before, deleted,
           UDFS_RECOVERY_SECTOR_SIZE);
    memcpy(plan->FidEdit.After, live,
           UDFS_RECOVERY_SECTOR_SIZE);
    plan->FidEditCount = 1;
    return UdfsRecoveryProbeValidLayout;
}

static UDFS_RECOVERY_PROBE_STATUS
GraphRun(const UDFS_RECOVERY_READER *reader, UDFS_RECOVERY_PROBE *result,
         const RECOVERY_EXTENT_LIST *mainFile,
         const RECOVERY_EXTENT_LIST *mirrorFile,
         const RECOVERY_EXTENT_LIST *bitmapFile,
         const uint8_t lvd[UDFS_RECOVERY_SECTOR_SIZE],
         uint32_t bitmapExtentBytes, UDFS_RECOVERY_REPAIR_PLAN *plan,
         uint8_t fsd[UDFS_RECOVERY_SECTOR_SIZE])
{
    RECOVERY_GRAPH *graph;
    UDFS_RECOVERY_PROBE_STATUS status = UdfsRecoveryProbeValidLayout;
    uint32_t metadataBytes, i;
    uint32_t fsdEncoded, rootEncoded;
    uint16_t fsdRef;

    /* The mount thread has a 12 KiB kernel stack and will issue lower-device
     * I/O while this graph is live.  Keep its sector caches off that stack. */
    graph = (RECOVERY_GRAPH *)reader->Allocate(reader->Context,
                                               sizeof(*graph));
    if (!graph) return UdfsRecoveryProbeNoMemory;
    memset(graph, 0, sizeof(*graph));
    graph->Reader = reader;
    graph->Result = result;
    graph->Metadata = mainFile;
    graph->BitmapFile = bitmapFile;
    graph->ScratchExtents = (RECOVERY_EXTENT_LIST *)reader->Allocate(
        reader->Context, sizeof(*graph->ScratchExtents));
    metadataBytes = (uint32_t)(((uint64_t)result->MetadataBlocks + 7) / 8);
    status = BitmapInitialize(reader, &graph->PhysicalOwned,
                               result->PartitionBlocks);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = BitmapInitialize(reader, &graph->PhysicalVisited,
                               result->PartitionBlocks);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = BitmapInitialize(reader, &graph->PhysicalDirs,
                               result->PartitionBlocks);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    graph->MetadataOwned = (uint8_t *)reader->Allocate(reader->Context,
                                                       metadataBytes);
    graph->MetadataVisited = (uint8_t *)reader->Allocate(reader->Context,
                                                         metadataBytes);
    graph->MetadataDirs = (uint8_t *)reader->Allocate(reader->Context,
                                                      metadataBytes);
    graph->MetadataInlineFileFes = (uint8_t *)reader->Allocate(
        reader->Context, metadataBytes);
    if (!graph->ScratchExtents || !graph->MetadataOwned ||
        !graph->MetadataVisited || !graph->MetadataDirs ||
        !graph->MetadataInlineFileFes) {
        status = UdfsRecoveryProbeNoMemory;
        goto done;
    }
    memset(graph->MetadataOwned, 0, metadataBytes);
    memset(graph->MetadataVisited, 0, metadataBytes);
    memset(graph->MetadataDirs, 0, metadataBytes);
    memset(graph->MetadataInlineFileFes, 0, metadataBytes);

    for (i = 0; i < mainFile->Count; ++i) {
        status = GraphOwn(graph, 0, mainFile->Items[i].Lbn,
                           mainFile->Items[i].Bytes);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
    }
    if (result->MetadataDuplicated)
        for (i = 0; i < mirrorFile->Count; ++i) {
            status = GraphOwn(graph, 0, mirrorFile->Items[i].Lbn,
                               mirrorFile->Items[i].Bytes);
            if (status != UdfsRecoveryProbeValidLayout) goto done;
        }
    status = GraphOwn(graph, 0, result->PhysicalBitmapLbn,
                       bitmapExtentBytes);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = GraphOwn(graph, 0, result->MetadataMainFeLbn,
                       UDFS_RECOVERY_SECTOR_SIZE);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = GraphOwn(graph, 0, result->MetadataMirrorFeLbn,
                       UDFS_RECOVERY_SECTOR_SIZE);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = GraphOwn(graph, 0, result->MetadataBitmapFeLbn,
                       UDFS_RECOVERY_SECTOR_SIZE);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    for (i = 0; i < bitmapFile->Count; ++i) {
        status = GraphOwn(graph, 0, bitmapFile->Items[i].Lbn,
                           bitmapFile->Items[i].Bytes);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
    }

    fsdEncoded = Read32(lvd + 248);
    fsdRef = Read16(lvd + 256);
    if (fsdEncoded >> 30 ||
        (fsdEncoded & 0x3fffffff) != UDFS_RECOVERY_SECTOR_SIZE) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    status = GraphOwn(graph, fsdRef, Read32(lvd + 252),
                       UDFS_RECOVERY_SECTOR_SIZE);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = GraphReadLogical(graph, fsdRef, Read32(lvd + 252), fsd);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = ValidateTag(fsd, 256, Read32(lvd + 252));
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    if (Read16(fsd + 10) < 416 - 16) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    rootEncoded = Read32(fsd + 400);
    if (rootEncoded >> 30 ||
        (rootEncoded & 0x3fffffff) != UDFS_RECOVERY_SECTOR_SIZE) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    status = GraphPush(graph, Read16(fsd + 408),
                       Read32(fsd + 404), rootEncoded & 0x3fffffff, 1,
                       Read16(fsd + 408), Read32(fsd + 404), 0, 0);
    if (status != UdfsRecoveryProbeValidLayout) goto done;

    while (graph->QueueCount) {
        RECOVERY_GRAPH_ENTRY entry = graph->Queue[--graph->QueueCount];
        status = GraphProcessFile(graph, &entry);
        if (status != UdfsRecoveryProbeValidLayout) {
            result->FailureObjectRef = entry.Ref;
            result->FailureObjectLbn = entry.Lbn;
            goto done;
        }
    }

    if (graph->FileReferences != result->FilesVisited) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }

    for (i = 0; i < (result->PartitionBlocks + 7ULL) / 8; ++i) {
        uint32_t byteOffset = 24 + i;
        uint32_t first = i * 8, remaining = result->PartitionBlocks - first;
        uint8_t value, owned, referencedFree, unowned;
        uint8_t mask = remaining < 8 ? (uint8_t)((1U << remaining) - 1) : 0xff;
        status = ReadCachedByte(reader, result, &graph->PhysicalBitmapCache,
                    result->PartitionStart + result->PhysicalBitmapLbn +
                    byteOffset / UDFS_RECOVERY_SECTOR_SIZE,
                    byteOffset % UDFS_RECOVERY_SECTOR_SIZE, &value);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        owned = BitmapReadByte(&graph->PhysicalOwned, i);
        referencedFree = value & owned & mask;
        unowned = (uint8_t)~(value | owned) & mask;
        if (referencedFree) {
            if (plan) {
                uint8_t remainingBits = referencedFree;
                while (remainingBits) {
                    uint32_t bit = FirstByteBit(remainingBits);
                    status = PlanOwnedPhysicalBlock(reader, result, plan,
                                                    first + bit);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                    remainingBits &= (uint8_t)(remainingBits - 1);
                }
            }
            if (!result->ReferencedFreePhysicalBlocks)
                result->FirstReferencedFreePhysicalLbn = first + FirstByteBit(referencedFree);
            result->ReferencedFreePhysicalBlocks += CountByteBits(referencedFree);
        }
        if (unowned) {
            if (!result->UnownedPhysicalBlocks)
                result->FirstUnownedPhysicalLbn = first + FirstByteBit(unowned);
            result->UnownedPhysicalBlocks += CountByteBits(unowned);
        }
    }
    for (i = 0; i < result->MetadataBlocks; ++i) {
        uint32_t bitmapLba, bitmapOffset;
        uint8_t value;
        status = MapExtentByte(result, bitmapFile, 24ULL + (i >> 3),
                               &bitmapLba, &bitmapOffset);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        status = ReadCachedByte(reader, result, &graph->MetadataBitmapCache,
                                bitmapLba, bitmapOffset, &value);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        if ((value >> (i & 7)) & 1) {
            if (BitIsSet(graph->MetadataOwned, i)) {
                if (result->MetadataDuplicated) {
                    uint32_t mainLba, mirrorLba;
                    status = MapMetadataBlock(result, mainFile, i, &mainLba);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                    status = MapMetadataBlock(result, mirrorFile, i, &mirrorLba);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                    status = ReadSector(reader, result, mainLba, fsd);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                    status = ReadSector(reader, result, mirrorLba,
                                        graph->PhysicalBitmapCache.Data);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                    if (RecoveryDifference(fsd, graph->PhysicalBitmapCache.Data,
                               UDFS_RECOVERY_SECTOR_SIZE) != 0) {
                        result->FailureLba = mainLba;
                        status = UdfsRecoveryProbeCorrupt;
                        goto done;
                    }
                    result->ReferencedFreeMirrorBlocksCompared++;
                }
                if (!result->ReferencedFreeMetadataBlocks)
                    result->FirstReferencedFreeMetadataLbn = i;
                if (BitIsSet(graph->MetadataInlineFileFes, i))
                    result->ReferencedFreeInlineFileFeBlocks++;
                if (result->ReferencedFreeMetadataBlocks <
                    UDFS_RECOVERY_MAX_REPAIR_BLOCKS)
                    result->ReferencedFreeMetadataLbn[
                        result->ReferencedFreeMetadataBlocks] = i;
                result->ReferencedFreeMetadataBlocks++;
                if (plan) {
                    status = PlanOwnedMetadataBlock(reader, result, bitmapFile,
                                                     plan, i);
                    if (status != UdfsRecoveryProbeValidLayout) goto done;
                }
            }
        } else if (!BitIsSet(graph->MetadataOwned, i)) {
            if (!result->UnownedMetadataBlocks)
                result->FirstUnownedMetadataLbn = i;
            result->UnownedMetadataBlocks++;
        }
    }
    if (result->FidSplitCount) {
        if (result->MirrorDirectorySplitCount ||
            !result->FidSplitSeen ||
            result->DirectoryLinkFixCount != 1 ||
            result->FidSplitParentLbn !=
                result->DirectoryLinkFixParentLbn ||
            result->FidSplitChildLbn !=
                result->DirectoryLinkFixChildLbn) {
            status = UdfsRecoveryProbeCorrupt;
            goto done;
        }
        if (plan) {
            status = PlanLiveFidCopy(reader, result, plan);
            if (status != UdfsRecoveryProbeValidLayout)
                goto done;
        }
    }
    if (result->MirrorDirectorySplitCount &&
        (!result->DirectoryLinkFixCount ||
         result->DirectoryLinkFixParentLbn !=
            result->MirrorDirectoryLbn)) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    if (result->DirectoryLinkFixCount) {
        if (result->UnownedPhysicalBlocks ||
            result->UnownedMetadataBlocks || result->OverlapBlocks ||
            (!result->MirrorDirectorySplitCount &&
             (!result->DirectoryLinkFixChildVerified ||
              result->ReferencedFreeMetadataBlocks != 1 ||
              result->FirstReferencedFreeMetadataLbn !=
                  result->DirectoryLinkFixChildLbn ||
              result->ReferencedFreePhysicalBlocks))) {
            status = UdfsRecoveryProbeCorrupt;
            goto done;
        }
        if (plan) {
            status = PlanParentLinkCount(reader, result, mainFile,
                                         mirrorFile, plan);
            if (status != UdfsRecoveryProbeValidLayout)
                goto done;
        }
    }
    result->OwnershipGraphScanned = 1;
    if (result->OverlapBlocks || result->ReferencedFreePhysicalBlocks ||
        result->ReferencedFreeMetadataBlocks || result->UnownedPhysicalBlocks ||
        result->UnownedMetadataBlocks)
        status = UdfsRecoveryProbeGraphMismatch;
    else
        result->CompleteOwnershipGraph = 1;
done:
    if (graph->ScratchExtents) reader->Free(reader->Context, graph->ScratchExtents);
    if (graph->Queue) reader->Free(reader->Context, graph->Queue);
    if (graph->UniqueIds) reader->Free(reader->Context, graph->UniqueIds);
    BitmapRelease(reader, &graph->PhysicalOwned);
    if (graph->MetadataOwned) reader->Free(reader->Context, graph->MetadataOwned);
    BitmapRelease(reader, &graph->PhysicalVisited);
    if (graph->MetadataVisited) reader->Free(reader->Context, graph->MetadataVisited);
    BitmapRelease(reader, &graph->PhysicalDirs);
    if (graph->MetadataDirs) reader->Free(reader->Context, graph->MetadataDirs);
    if (graph->MetadataInlineFileFes)
        reader->Free(reader->Context, graph->MetadataInlineFileFes);
    reader->Free(reader->Context, graph);
    return status;
}

typedef struct _RECOVERY_LAYOUT_WORK {
    uint8_t Sector[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t Pd[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t Lvd[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t MainSector[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t MirrorSector[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t PrevailingLvid[UDFS_RECOVERY_SECTOR_SIZE];
    RECOVERY_SECTOR_CACHE PhysicalCache;
    RECOVERY_SECTOR_CACHE MetadataCache;
    RECOVERY_EXTENT_LIST Lists[3];
} RECOVERY_LAYOUT_WORK;

static void
RecoveryAnchorCandidates(uint32_t sectorCount, uint32_t anchors[8])
{
    uint32_t last = sectorCount - 1;
    anchors[0] = 256;
    anchors[1] = 512;
    anchors[2] = last - 256;
    anchors[3] = last - 255;
    anchors[4] = last - 258;
    anchors[5] = last - 2;
    anchors[6] = last;
    anchors[7] = last - 512;
}

/* Only the single-session disk class is supported. Keep the ordinary mount's
 * anchor order (duplicate session/track candidates omitted), and never select
 * another anchor merely because an accepted anchor's ownership graph fails. */
static UDFS_RECOVERY_PROBE_STATUS
ReadRecoveryDescriptors(const UDFS_RECOVERY_READER *reader,
                        UDFS_RECOVERY_PROBE *result, uint32_t start,
                        uint32_t bytes, uint8_t *sector,
                        uint8_t *pd, uint8_t *lvd)
{
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t i, count;
    int havePd = 0, haveLvd = 0, havePvd = 0;

    if (!bytes || (bytes & (UDFS_RECOVERY_SECTOR_SIZE - 1)))
        return UdfsRecoveryProbeCorrupt;
    if (bytes > 256 * UDFS_RECOVERY_SECTOR_SIZE)
        return UdfsRecoveryProbeUnsupported;
    count = bytes / UDFS_RECOVERY_SECTOR_SIZE;
    if (start >= reader->SectorCount || count > reader->SectorCount - start)
        return UdfsRecoveryProbeCorrupt;
    for (i = 0; i < count; ++i) {
        uint16_t kind;
        result->FailureLba = start + i;
        status = ReadSector(reader, result, start + i, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        kind = Read16(sector);
        status = ValidateTag(sector, kind, start + i);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        switch (kind) {
        case 1:
            if (havePvd) return UdfsRecoveryProbeUnsupported;
            havePvd = 1;
            break;
        case 4:
        case 7:
            break;
        case 5:
            if (havePd) return UdfsRecoveryProbeUnsupported;
            if (Read16(sector + 10) < 196 - 16)
                return UdfsRecoveryProbeCorrupt;
            memcpy(pd, sector, UDFS_RECOVERY_SECTOR_SIZE);
            havePd = 1;
            break;
        case 6:
            if (haveLvd) return UdfsRecoveryProbeUnsupported;
            /* Include the complete supported partition map in the CRC. */
            if (Read16(sector + 10) < 510 - 16)
                return UdfsRecoveryProbeCorrupt;
            memcpy(lvd, sector, UDFS_RECOVERY_SECTOR_SIZE);
            haveLvd = 1;
            break;
        case 8:
            if (!havePd || !haveLvd || !havePvd)
                return UdfsRecoveryProbeCorrupt;
            result->VdsStartLba = start;
            result->FailureLba = 0;
            return UdfsRecoveryProbeValidLayout;
        default:
            /* In particular, do not silently ignore a VDS continuation and
             * validate a different descriptor set from the ordinary mount. */
            return UdfsRecoveryProbeUnsupported;
        }
    }
    return UdfsRecoveryProbeCorrupt;
}

static UDFS_RECOVERY_PROBE_STATUS
SelectRecoveryDescriptors(const UDFS_RECOVERY_READER *reader,
                          UDFS_RECOVERY_PROBE *result, uint8_t *sector,
                          uint8_t *pd, uint8_t *lvd)
{
    UDFS_RECOVERY_PROBE_STATUS status = UdfsRecoveryProbeCorrupt;
    uint32_t anchors[8];
    uint32_t i, mainStart, mainBytes, reserveStart, reserveBytes;

    RecoveryAnchorCandidates(reader->SectorCount, anchors);
    for (i = 0; i < 8; ++i) {
        if (!anchors[i] || anchors[i] >= reader->SectorCount) continue;
        result->FailureLba = anchors[i];
        status = ReadSector(reader, result, anchors[i], sector);
        if (status == UdfsRecoveryProbeValidLayout)
            status = ValidateTag(sector, 2, anchors[i]);
        if (status == UdfsRecoveryProbeUnsupported) return status;
        if (status != UdfsRecoveryProbeValidLayout) continue;
        result->AnchorLba = anchors[i];
        /* A valid earlier anchor remains authoritative, even if its VDS is
         * unusable. Falling through to a later one could recover a stale view. */
        if (Read16(sector + 10) < 32 - 16)
            return UdfsRecoveryProbeCorrupt;
        mainBytes = Read32(sector + 16);
        mainStart = Read32(sector + 20);
        reserveBytes = Read32(sector + 24);
        reserveStart = Read32(sector + 28);
        result->MainVdsStartLba = mainStart;
        result->MainVdsBytes = mainBytes;
        result->ReserveVdsStartLba = reserveStart;
        result->ReserveVdsBytes = reserveBytes;
        status = ReadRecoveryDescriptors(reader, result, mainStart, mainBytes,
                                          sector, pd, lvd);
        if (status != UdfsRecoveryProbeCorrupt &&
            status != UdfsRecoveryProbeIoError)
            return status;
        return ReadRecoveryDescriptors(reader, result, reserveStart,
                                         reserveBytes, sector, pd, lvd);
    }
    return status;
}

/* Match UDFLoadLogicalVolInt's prevailing descriptor walk: an LVID with a
 * nextIntegrityExt jumps to that extent before the remaining sectors of the
 * current extent. The earlier CLOSED descriptor must not hide a later OPEN
 * checkpoint. Bound both each extent and the total walk before any repair. */
static UDFS_RECOVERY_PROBE_STATUS
ReadPrevailingIntegrity(const UDFS_RECOVERY_READER *reader,
                        UDFS_RECOVERY_PROBE *result, uint32_t extentBytes,
                        uint32_t extentLba, uint8_t *sector,
                        uint8_t *prevailing, uint32_t *prevailingLba,
                        uint8_t *integrityType,
                        uint8_t *checksumRepair)
{
    uint32_t visited = 0;
    uint32_t anchors[8];
    uint8_t lastType = 0xff;
    uint16_t previousVersion = 0, previousSerial = 0;
    uint16_t previousCrcLength = 0;
    int linkedFromClosed = 0;
    int found = 0;

    *integrityType = 0xff;
    if (prevailingLba) *prevailingLba = 0;
    if (checksumRepair) *checksumRepair = 0;
    RecoveryAnchorCandidates(reader->SectorCount, anchors);
    for (;;) {
        uint32_t i, count;

        if (!extentBytes || (extentBytes & (UDFS_RECOVERY_SECTOR_SIZE - 1)))
            return UdfsRecoveryProbeCorrupt;
        if (extentBytes > 256 * UDFS_RECOVERY_SECTOR_SIZE)
            return UdfsRecoveryProbeUnsupported;
        count = extentBytes / UDFS_RECOVERY_SECTOR_SIZE;
        if (extentLba >= reader->SectorCount ||
            count > reader->SectorCount - extentLba)
            return UdfsRecoveryProbeCorrupt;
        /* Recovery can rewrite the prevailing LVID. Do not treat a valid
         * descriptor tag inside the physical partition as proof that its
         * sector is reserved for the integrity sequence: it may be owned by
         * a file, metadata extent or bitmap. Refuse this layout before any
         * repair instead of writing through that other owner's sector. */
        if ((uint64_t)extentLba <
                (uint64_t)result->PartitionStart + result->PartitionBlocks &&
            (uint64_t)result->PartitionStart <
                (uint64_t)extentLba + count) {
            result->FailureLba = extentLba > result->PartitionStart ?
                extentLba : result->PartitionStart;
            return UdfsRecoveryProbeCorrupt;
        }
        /* The volume descriptor sequences are allocated extents, including
         * their sectors after the terminating descriptor. A valid LVID tag
         * there or at an anchor candidate is not proof of LVID ownership.
         * An accepted checkpoint may be rewritten during repair. */
        {
            uint32_t starts[2], bytes[2], j;
            starts[0] = result->MainVdsStartLba;
            starts[1] = result->ReserveVdsStartLba;
            bytes[0] = result->MainVdsBytes;
            bytes[1] = result->ReserveVdsBytes;
            for (j = 0; j < 2; ++j) {
                uint32_t blocks;
                if (!bytes[j]) {
                    if (j == 0) return UdfsRecoveryProbeCorrupt;
                    continue;
                }
                if (bytes[j] & (UDFS_RECOVERY_SECTOR_SIZE - 1))
                    return UdfsRecoveryProbeCorrupt;
                blocks = bytes[j] / UDFS_RECOVERY_SECTOR_SIZE;
                if (starts[j] >= reader->SectorCount ||
                    blocks > reader->SectorCount - starts[j])
                    return UdfsRecoveryProbeCorrupt;
                if ((uint64_t)extentLba < (uint64_t)starts[j] + blocks &&
                    (uint64_t)starts[j] < (uint64_t)extentLba + count) {
                    result->FailureLba = extentLba > starts[j] ?
                        extentLba : starts[j];
                    return UdfsRecoveryProbeCorrupt;
                }
            }
            for (j = 0; j < 8; ++j) {
                if (anchors[j] < reader->SectorCount &&
                    anchors[j] >= extentLba &&
                    anchors[j] - extentLba < count) {
                    result->FailureLba = anchors[j];
                    return UdfsRecoveryProbeCorrupt;
                }
            }
        }
        for (i = 0; i < count; ++i) {
            uint32_t lba = extentLba + i;
            uint32_t nextBytes, nextLba;
            uint16_t kind;
            uint8_t repaired = 0;
            UDFS_RECOVERY_PROBE_STATUS status;

            result->FailureLba = lba;
            if (++visited > 1024)
                return UdfsRecoveryProbeUnsupported;
            status = ReadSector(reader, result, lba, sector);
            if (status != UdfsRecoveryProbeValidLayout) return status;
            kind = Read16(sector);
            if (kind == 8) {
                status = ValidateTag(sector, 8, lba);
                if (status != UdfsRecoveryProbeValidLayout) return status;
                if (!found) return UdfsRecoveryProbeCorrupt;
                result->FailureLba = 0;
                *integrityType = lastType;
                return UdfsRecoveryProbeValidLayout;
            }
            if (kind != 9) return UdfsRecoveryProbeCorrupt;
            status = NormalizeOpenLvidTagChecksum(sector, lba,
                         linkedFromClosed && count == 1 && i == 0 &&
                         Read16(sector + 2) == previousVersion &&
                         Read16(sector + 6) == previousSerial &&
                         Read16(sector + 10) == previousCrcLength,
                         &repaired);
            if (status != UdfsRecoveryProbeValidLayout) return status;
            if (repaired && checksumRepair) *checksumRepair = 1;
            /* A CLOSED decision requires CRC coverage of the integrity type,
             * free/size tables and counters, not just a valid tag checksum. */
            if (Read16(sector + 10) < 136 - 16)
                return UdfsRecoveryProbeCorrupt;
            if (Read32(sector + 72) != 2 || Read32(sector + 28) > 1)
                return UdfsRecoveryProbeUnsupported;
            lastType = (uint8_t)Read32(sector + 28);
            if (prevailing) memcpy(prevailing, sector,
                                   UDFS_RECOVERY_SECTOR_SIZE);
            if (prevailingLba) *prevailingLba = lba;
            found = 1;
            nextBytes = Read32(sector + 32);
            if (!nextBytes) continue;
            nextLba = Read32(sector + 36);
            if (nextLba == lba) return UdfsRecoveryProbeCorrupt;
            linkedFromClosed = lastType == 1;
            previousVersion = Read16(sector + 2);
            previousSerial = Read16(sector + 6);
            previousCrcLength = Read16(sector + 10);
            extentBytes = nextBytes;
            extentLba = nextLba;
            goto next_extent;
        }
        if (!found) return UdfsRecoveryProbeCorrupt;
        result->FailureLba = 0;
        *integrityType = lastType;
        return UdfsRecoveryProbeValidLayout;
next_extent:
        ;
    }
}

UDFS_RECOVERY_PROBE_STATUS
UdfsRecoveryPeekIntegrity(const UDFS_RECOVERY_READER *reader,
                          uint8_t *integrityType)
{
    uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t pd[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t lvd[UDFS_RECOVERY_SECTOR_SIZE];
    UDFS_RECOVERY_PROBE scratch;
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t extentBytes, extentLba;

    if (!reader || !reader->ReadSector || !integrityType ||
        reader->SectorCount <= 256)
        return UdfsRecoveryProbeInvalidInput;
    *integrityType = 0xff;
    memset(&scratch, 0, sizeof(scratch));
    status = SelectRecoveryDescriptors(reader, &scratch, sector, pd, lvd);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (Read32(lvd + 212) != UDFS_RECOVERY_SECTOR_SIZE ||
        Read32(lvd + 268) != 2 || Read32(lvd + 264) != 70 ||
        lvd[440] != 1 || lvd[441] != 6 ||
        lvd[446] != 2 || lvd[447] != 64 ||
        RecoveryDifference(lvd + 451,
                           "*UDF Metadata Partition", 23) != 0 ||
        lvd[504] != 1)
        return UdfsRecoveryProbeUnsupported;
    scratch.PartitionStart = Read32(pd + 188);
    scratch.PartitionBlocks = Read32(pd + 192);
    if (!scratch.PartitionBlocks ||
        scratch.PartitionStart >= reader->SectorCount ||
        scratch.PartitionBlocks >
            reader->SectorCount - scratch.PartitionStart)
        return UdfsRecoveryProbeCorrupt;

    extentBytes = Read32(lvd + 432) & 0x3fffffff;
    extentLba = Read32(lvd + 436);
    return ReadPrevailingIntegrity(reader, &scratch, extentBytes, extentLba,
                                   sector, NULL, NULL, integrityType, NULL);
}

static UDFS_RECOVERY_PROBE_STATUS
ProbeLayout(const UDFS_RECOVERY_READER *reader,
             UDFS_RECOVERY_PROBE *result, UDFS_RECOVERY_REPAIR_PLAN *plan)
{
    RECOVERY_LAYOUT_WORK *work;
    uint8_t *sector, *pd, *lvd;
    uint8_t *mainSector, *mirrorSector, *prevailingLvid;
    RECOVERY_SECTOR_CACHE *physicalCache, *metadataCache;
    RECOVERY_EXTENT_LIST *mainFile, *mirrorFile, *bitmapFile;
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t i, partitionNumber;
    uint32_t mapLength, bitmapBytes, bitmapExtentBytes;
    const uint8_t *metadataMap;

    if (!result) return UdfsRecoveryProbeInvalidInput;
    memset(result, 0, sizeof(*result));
    result->FirstReferencedFreePhysicalLbn = UINT32_MAX;
    result->FirstReferencedFreeMetadataLbn = UINT32_MAX;
    result->FirstUnownedPhysicalLbn = UINT32_MAX;
    result->FirstUnownedMetadataLbn = UINT32_MAX;
    result->Status = UdfsRecoveryProbeInvalidInput;
    if (!reader || !reader->ReadSector || !reader->Allocate ||
        !reader->Free || reader->SectorCount <= 256)
        return result->Status;
    work = (RECOVERY_LAYOUT_WORK *)reader->Allocate(reader->Context,
                                                    sizeof(*work));
    if (!work) {
        result->Status = UdfsRecoveryProbeNoMemory;
        return result->Status;
    }
    memset(work, 0, sizeof(*work));
    sector = work->Sector;
    pd = work->Pd;
    lvd = work->Lvd;
    mainSector = work->MainSector;
    mirrorSector = work->MirrorSector;
    prevailingLvid = work->PrevailingLvid;
    physicalCache = &work->PhysicalCache;
    metadataCache = &work->MetadataCache;
    mainFile = &work->Lists[0];
    mirrorFile = &work->Lists[1];
    bitmapFile = &work->Lists[2];

    status = SelectRecoveryDescriptors(reader, result, sector, pd, lvd);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    if (Read32(lvd + 212) != UDFS_RECOVERY_SECTOR_SIZE) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    partitionNumber = Read16(pd + 22);
    result->PartitionStart = Read32(pd + 188);
    result->PartitionBlocks = Read32(pd + 192);
    if (!result->PartitionBlocks ||
        result->PartitionStart >= reader->SectorCount ||
        result->PartitionBlocks > reader->SectorCount - result->PartitionStart) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    mapLength = Read32(lvd + 264);
    if (Read32(lvd + 268) != 2 || mapLength != 70 ||
        lvd[440] != 1 || lvd[441] != 6 ||
        Read16(lvd + 444) != partitionNumber ||
        lvd[446] != 2 || lvd[447] != 64) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    metadataMap = lvd + 446;
    if (RecoveryDifference(metadataMap + 5, "*UDF Metadata Partition", 23) != 0 ||
        Read16(metadataMap + 38) != partitionNumber ||
        (metadataMap[58] & ~1U)) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    result->MetadataDuplicated = metadataMap[58] & 1;
    result->MetadataMainFeLbn = Read32(metadataMap + 40);
    result->MetadataMirrorFeLbn = Read32(metadataMap + 44);
    result->MetadataBitmapFeLbn = Read32(metadataMap + 48);

    status = ReadFileExtents(reader, result, result->MetadataMainFeLbn,
                             250, mainFile);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = ReadFileExtents(reader, result, result->MetadataMirrorFeLbn,
                             251, mirrorFile);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    if (mainFile->FileBytes != mirrorFile->FileBytes ||
        mainFile->FileBytes != (uint64_t)mainFile->TotalBlocks *
                              UDFS_RECOVERY_SECTOR_SIZE ||
        mirrorFile->FileBytes != (uint64_t)mirrorFile->TotalBlocks *
                                UDFS_RECOVERY_SECTOR_SIZE) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    result->MetadataBlocks = mainFile->TotalBlocks;
    result->MainExtents = mainFile->Count;
    result->MirrorExtents = mirrorFile->Count;
    if (result->MetadataDuplicated) {
        uint32_t m, n;
        for (m = 0; m < mainFile->Count; ++m)
            for (n = 0; n < mirrorFile->Count; ++n)
                if (RangesOverlap(&mainFile->Items[m],
                                  &mirrorFile->Items[n])) {
                    status = UdfsRecoveryProbeCorrupt;
                    goto done;
                }
    } else if (mainFile->Count != mirrorFile->Count ||
               RecoveryDifference(mainFile->Items, mirrorFile->Items,
                      mainFile->Count * sizeof(RECOVERY_EXTENT)) != 0) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }

    status = ReadFileExtents(reader, result, result->MetadataBitmapFeLbn,
                             252, bitmapFile);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    {
        /* The first bitmap descriptor is no longer needed when mirror
         * comparisons start, so reuse the existing heap sector. */
        uint8_t *descriptor = mainSector;
        uint32_t bitmapLba, bitmapOffset, tagLbn;
        status = MapExtentByte(result, bitmapFile, 0,
                               &bitmapLba, &bitmapOffset);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        status = ReadSector(reader, result, bitmapLba, sector);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        if (bitmapFile->Inline) {
            if (bitmapFile->FileBytes >
                UDFS_RECOVERY_SECTOR_SIZE - bitmapOffset) {
                status = UdfsRecoveryProbeCorrupt;
                goto done;
            }
            memset(descriptor, 0, UDFS_RECOVERY_SECTOR_SIZE);
            memcpy(descriptor, sector + bitmapOffset,
                   (size_t)bitmapFile->FileBytes);
            if (Read16(descriptor + 10) > bitmapFile->FileBytes - 16) {
                status = UdfsRecoveryProbeCorrupt;
                goto done;
            }
            tagLbn = bitmapFile->InlineFeLbn;
        } else {
            if (bitmapOffset || !bitmapFile->Count) {
                status = UdfsRecoveryProbeCorrupt;
                goto done;
            }
            memcpy(descriptor, sector, UDFS_RECOVERY_SECTOR_SIZE);
            tagLbn = bitmapFile->Items[0].Lbn;
        }
        status = ValidateTag(descriptor, 0x108, tagLbn);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        result->MetadataBitmapBits = Read32(descriptor + 16);
        bitmapBytes = Read32(descriptor + 20);
        if (result->MetadataBitmapBits < result->MetadataBlocks ||
            bitmapBytes < (result->MetadataBitmapBits + 7U) / 8U ||
            bitmapFile->FileBytes < 24ULL + bitmapBytes) {
            status = UdfsRecoveryProbeCorrupt;
            goto done;
        }
    }

    bitmapExtentBytes = Read32(pd + 64) & 0x3fffffff;
    result->PhysicalBitmapLbn = Read32(pd + 68);
    if (bitmapExtentBytes < 24ULL + (result->PartitionBlocks + 7ULL) / 8ULL ||
        result->PhysicalBitmapLbn >= result->PartitionBlocks ||
        (bitmapExtentBytes + 511ULL) / 512ULL >
            result->PartitionBlocks - result->PhysicalBitmapLbn) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    status = ReadSector(reader, result,
                        result->PartitionStart + result->PhysicalBitmapLbn,
                        sector);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    status = ValidateTag(sector, 0x108, result->PhysicalBitmapLbn);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    if (Read32(sector + 16) != result->PartitionBlocks ||
        Read32(sector + 20) < (result->PartitionBlocks + 7ULL) / 8ULL) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }

    for (i = 0; i < (result->PartitionBlocks + 7ULL) / 8; ++i) {
        uint32_t byteOffset = 24 + i;
        uint32_t remaining = result->PartitionBlocks - i * 8;
        uint8_t value;
        status = ReadCachedByte(reader, result, physicalCache,
                    result->PartitionStart + result->PhysicalBitmapLbn +
                    byteOffset / UDFS_RECOVERY_SECTOR_SIZE,
                    byteOffset % UDFS_RECOVERY_SECTOR_SIZE, &value);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        if (remaining < 8) value &= (uint8_t)((1U << remaining) - 1);
        result->PhysicalFreeBlocks += CountByteBits(value);
    }

    for (i = 0; i < result->MetadataBlocks; ++i) {
        uint32_t bitmapLba, bitmapOffset;
        uint8_t value;
        status = MapExtentByte(result, bitmapFile, 24ULL + (i >> 3),
                               &bitmapLba, &bitmapOffset);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        status = ReadCachedByte(reader, result, metadataCache,
                                bitmapLba, bitmapOffset, &value);
        if (status != UdfsRecoveryProbeValidLayout) goto done;
        if ((value >> (i & 7)) & 1) {
            result->MetadataFreeBlocks++;
        } else if (result->MetadataDuplicated) {
            uint32_t mainLba, mirrorLba;
            status = MapMetadataBlock(result, mainFile, i, &mainLba);
            if (status != UdfsRecoveryProbeValidLayout) goto done;
            status = MapMetadataBlock(result, mirrorFile, i, &mirrorLba);
            if (status != UdfsRecoveryProbeValidLayout) goto done;
            status = ReadSector(reader, result, mainLba, mainSector);
            if (status != UdfsRecoveryProbeValidLayout) goto done;
            status = ReadSector(reader, result, mirrorLba, mirrorSector);
            if (status != UdfsRecoveryProbeValidLayout) goto done;
            if (RecoveryDifference(mainSector, mirrorSector,
                       UDFS_RECOVERY_SECTOR_SIZE) != 0) {
                int liveOnMirror;
                uint32_t childLbn, recordOffset;
                if (result->MirrorDirectorySplitCount ||
                    result->FidSplitCount) {
                    result->FailureLba = mainLba;
                    status = UdfsRecoveryProbeCorrupt;
                    goto done;
                }
                if (DirectoryFePairDiffersOnlyInLinkCount(
                        mainSector, mirrorSector, i)) {
                    result->MirrorDirectorySplitCount = 1;
                    result->MirrorDirectoryLbn = i;
                    result->MirrorDirectoryMainLinks =
                        Read16(mainSector + 48);
                    result->MirrorDirectoryMirrorLinks =
                        Read16(mirrorSector + 48);
                } else if (DirectoryFidPairLiveDeleted(
                               mainSector, mirrorSector, i,
                               &liveOnMirror, &childLbn,
                               &recordOffset)) {
                    result->FidSplitCount = 1;
                    result->FidSplitLbn = i;
                    result->FidSplitMainLba = mainLba;
                    result->FidSplitMirrorLba = mirrorLba;
                    result->FidSplitChildLbn = childLbn;
                    result->FidSplitRecordOffset = recordOffset;
                    result->FidSplitLiveOnMirror =
                        (uint8_t)liveOnMirror;
                } else {
                    result->FailureLba = mainLba;
                    status = UdfsRecoveryProbeCorrupt;
                    goto done;
                }
            }
            result->AllocatedMirrorBlocksCompared++;
        }
    }
    result->BitmapContentsScanned = 1;

    status = ReadPrevailingIntegrity(reader, result,
                Read32(lvd + 432) & 0x3fffffff, Read32(lvd + 436),
                sector, prevailingLvid, &result->PrevailingLvidLba,
                &result->LvidIntegrityType,
                &result->LvidTagChecksumRepair);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    if (Read16(prevailingLvid + 10) < 136 - 16) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    if (Read32(prevailingLvid + 72) != 2 ||
        Read32(prevailingLvid + 28) > 1) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    result->LvidIntegrityType = (uint8_t)Read32(prevailingLvid + 28);
    result->LvidPhysicalFreeBlocks = Read32(prevailingLvid + 80);
    result->LvidMetadataFreeBlocks = Read32(prevailingLvid + 84);
    result->LvidPhysicalSizeBlocks = Read32(prevailingLvid + 88);
    result->LvidMetadataSizeBlocks = Read32(prevailingLvid + 92);
    result->LvidNextUniqueId = Read64(prevailingLvid + 40);
    result->LvidFileCount = Read32(prevailingLvid + 128);
    result->LvidDirectoryCount = Read32(prevailingLvid + 132);
    result->LvidCountersMatch =
        result->LvidPhysicalFreeBlocks == result->PhysicalFreeBlocks &&
        result->LvidMetadataFreeBlocks == result->MetadataFreeBlocks &&
        result->LvidPhysicalSizeBlocks == result->PartitionBlocks &&
        result->LvidMetadataSizeBlocks == result->MetadataBlocks;
    status = GraphRun(reader, result, mainFile, mirrorFile,
                      bitmapFile, lvd, bitmapExtentBytes, plan, sector);
    if (result->OwnershipGraphScanned)
        result->LvidCountersMatch = result->LvidCountersMatch &&
            result->LvidFileCount == result->FilesVisited &&
            result->LvidDirectoryCount == result->DirectoriesVisited &&
            result->LvidNextUniqueId > result->MaxUniqueId;
    if (status == UdfsRecoveryProbeValidLayout &&
        !result->LvidCountersMatch)
        status = UdfsRecoveryProbeLvidMismatch;
    /* Probing is read-only. Any checkpoint still requires a repair plan,
     * lower-device barriers and verification by UdfsRecoveryApplyRepair. */
done:
    result->Status = status;
    reader->Free(reader->Context, work);
    return status;
}

UDFS_RECOVERY_PROBE_STATUS
UdfsRecoveryProbeLayout(const UDFS_RECOVERY_READER *reader,
                        UDFS_RECOVERY_PROBE *result)
{
    return ProbeLayout(reader, result, NULL);
}

/* A fully walked, duplicate-free namespace with an exact physical owner graph
 * may account for metadata still marked free. Never free orphan allocations,
 * repair overlap, choose between conflicting mirrors, or infer file data. */
static int
GraphCanRecover(const UDFS_RECOVERY_PROBE *probe)
{
    return probe->LvidIntegrityType == 0 && probe->MetadataDuplicated &&
        probe->BitmapContentsScanned && probe->OwnershipGraphScanned &&
        (!probe->FidSplitCount ||
         (probe->FidSplitCount == 1 &&
          !probe->MirrorDirectorySplitCount &&
          probe->FidSplitSeen &&
          probe->DirectoryLinkFixCount == 1 &&
          probe->FidSplitParentLbn ==
              probe->DirectoryLinkFixParentLbn &&
          probe->FidSplitChildLbn ==
              probe->DirectoryLinkFixChildLbn)) &&
        (!probe->MirrorDirectorySplitCount ||
         (probe->MirrorDirectorySplitCount == 1 &&
          probe->DirectoryLinkFixCount == 1 &&
          probe->DirectoryLinkFixParentLbn ==
              probe->MirrorDirectoryLbn)) &&
        (!probe->DirectoryLinkFixCount ||
         (probe->DirectoryLinkFixCount == 1 &&
          (probe->MirrorDirectorySplitCount ||
           (probe->DirectoryLinkFixChildVerified &&
            probe->ReferencedFreePhysicalBlocks == 0 &&
            probe->ReferencedFreeMetadataBlocks == 1 &&
            probe->FirstReferencedFreeMetadataLbn ==
                probe->DirectoryLinkFixChildLbn)))) &&
        !probe->UnownedPhysicalBlocks &&
        !probe->UnownedMetadataBlocks && !probe->OverlapBlocks &&
        probe->ReferencedFreeMirrorBlocksCompared ==
            probe->ReferencedFreeMetadataBlocks &&
        probe->LvidPhysicalFreeBlocks <= probe->PartitionBlocks &&
        probe->LvidPhysicalSizeBlocks == probe->PartitionBlocks &&
        probe->PhysicalFreeBlocks >= probe->ReferencedFreePhysicalBlocks &&
        probe->MetadataFreeBlocks >= probe->ReferencedFreeMetadataBlocks &&
        probe->MaxUniqueId != UINT64_MAX &&
        (probe->Status == UdfsRecoveryProbeValidLayout ||
         probe->Status == UdfsRecoveryProbeGraphMismatch ||
         probe->Status == UdfsRecoveryProbeLvidMismatch);
}

UDFS_RECOVERY_PROBE_STATUS
UdfsRecoveryPrepareRepair(const UDFS_RECOVERY_READER *reader,
                          const UDFS_RECOVERY_PROBE *probe,
                          const uint8_t recordingTime[12],
                          UDFS_RECOVERY_REPAIR_PLAN *plan)
{
    UDFS_RECOVERY_PROBE check;
    UDFS_RECOVERY_PROBE_STATUS status;
    UDFS_RECOVERY_SECTOR_EDIT *edit;
    uint8_t normalizedLvid[UDFS_RECOVERY_SECTOR_SIZE];
    uint8_t repaired;
    uint32_t i, newPhysicalFree, newMetadataFree, crcLength, checksum;
    uint16_t crc;
    uint64_t nextUniqueId;

    if (!reader || !reader->ReadSector || !reader->Allocate ||
        !reader->Free || !probe || !recordingTime || !plan)
        return UdfsRecoveryProbeInvalidInput;
    memset(plan, 0, sizeof(*plan));
    if (!GraphCanRecover(probe)) return UdfsRecoveryProbeUnsupported;

    /* Rebuild from the current complete graph while collecting edits. A plan
     * never depends on a caller's truncated list of missing blocks. Exclusive
     * mount access must span probe, plan and apply. */
    status = ProbeLayout(reader, &check, plan);
    if (!GraphCanRecover(&check) ||
        RecoveryDifference(&check, probe, sizeof(check)) != 0) {
        if (status == UdfsRecoveryProbeValidLayout ||
            status == UdfsRecoveryProbeGraphMismatch ||
            status == UdfsRecoveryProbeLvidMismatch)
            status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    edit = &plan->LvidEdit;
    edit->Lba = probe->PrevailingLvidLba;
    status = ReadSector(reader, &check, edit->Lba, edit->Before);
    if (status != UdfsRecoveryProbeValidLayout) goto done;
    memcpy(normalizedLvid, edit->Before, UDFS_RECOVERY_SECTOR_SIZE);
    status = NormalizeOpenLvidTagChecksum(normalizedLvid, edit->Lba,
                     probe->LvidTagChecksumRepair, &repaired);
    if (status != UdfsRecoveryProbeValidLayout ||
        repaired != probe->LvidTagChecksumRepair) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }
    if (Read32(edit->Before + 28) != 0 ||
        Read32(edit->Before + 80) != probe->LvidPhysicalFreeBlocks ||
        Read32(edit->Before + 84) != probe->LvidMetadataFreeBlocks ||
        Read32(edit->Before + 88) != probe->LvidPhysicalSizeBlocks ||
        Read32(edit->Before + 92) != probe->LvidMetadataSizeBlocks ||
        Read64(edit->Before + 40) != probe->LvidNextUniqueId ||
        Read32(edit->Before + 128) != probe->LvidFileCount ||
        Read32(edit->Before + 132) != probe->LvidDirectoryCount) {
        status = UdfsRecoveryProbeCorrupt;
        goto done;
    }

    newPhysicalFree = probe->PhysicalFreeBlocks -
                      probe->ReferencedFreePhysicalBlocks;
    newMetadataFree = probe->MetadataFreeBlocks -
                      probe->ReferencedFreeMetadataBlocks;
    nextUniqueId = probe->MaxUniqueId + 1;
    if (nextUniqueId < probe->LvidNextUniqueId)
        nextUniqueId = probe->LvidNextUniqueId;
    memcpy(edit->After, normalizedLvid, UDFS_RECOVERY_SECTOR_SIZE);
    memcpy(edit->After + 16, recordingTime, 12);
    Write32(edit->After + 28, 1);
    Write64(edit->After + 40, nextUniqueId);
    Write32(edit->After + 80, newPhysicalFree);
    Write32(edit->After + 84, newMetadataFree);
    Write32(edit->After + 92, probe->MetadataBlocks);
    Write32(edit->After + 128, probe->FilesVisited);
    Write32(edit->After + 132, probe->DirectoriesVisited);
    crcLength = Read16(edit->After + 10);
    if (crcLength > UDFS_RECOVERY_SECTOR_SIZE - 16) {
        status = UdfsRecoveryProbeUnsupported;
        goto done;
    }
    crc = TagCrc(edit->After + 16, crcLength);
    edit->After[8] = (uint8_t)crc;
    edit->After[9] = (uint8_t)(crc >> 8);
    edit->After[4] = 0;
    checksum = 0;
    for (i = 0; i < 16; ++i)
        if (i != 4) checksum += edit->After[i];
    edit->After[4] = (uint8_t)checksum;
    status = ValidateTag(edit->After, 9, edit->Lba);
    if (status == UdfsRecoveryProbeValidLayout) {
        plan->LvidTagChecksumRepair = repaired;
        plan->Ready = 1;
    }
done:
    if (status != UdfsRecoveryProbeValidLayout)
        memset(plan, 0, sizeof(*plan));
    return status;
}

UDFS_RECOVERY_PROBE_STATUS
UdfsRecoveryApplyRepair(const UDFS_RECOVERY_READER *reader,
                        const UDFS_RECOVERY_REPAIR_PLAN *plan,
                        UDFS_RECOVERY_PROBE *after)
{
    uint8_t sector[UDFS_RECOVERY_SECTOR_SIZE];
    UDFS_RECOVERY_PROBE_STATUS status;
    uint32_t i, j;
    uint8_t repaired;

    if (!reader || !reader->ReadSector || !reader->WriteSector ||
        !reader->Flush || !reader->Allocate || !reader->Free ||
        !plan || !after || !plan->Ready ||
        plan->BitmapEditCount > UDFS_RECOVERY_MAX_BITMAP_EDITS ||
        plan->FeEditCount > 2 ||
        plan->FidEditCount > 1 ||
        plan->LvidEdit.Lba >= reader->SectorCount ||
        plan->LvidTagChecksumRepair > 1 ||
        ValidateTag(plan->LvidEdit.After, 9,
                    plan->LvidEdit.Lba) != UdfsRecoveryProbeValidLayout ||
        Read32(plan->LvidEdit.Before + 28) != 0 ||
        Read32(plan->LvidEdit.After + 28) != 1)
        return UdfsRecoveryProbeInvalidInput;

    memcpy(sector, plan->LvidEdit.Before, UDFS_RECOVERY_SECTOR_SIZE);
    status = NormalizeOpenLvidTagChecksum(sector, plan->LvidEdit.Lba,
                     plan->LvidTagChecksumRepair, &repaired);
    if (status != UdfsRecoveryProbeValidLayout ||
        repaired != plan->LvidTagChecksumRepair)
        return UdfsRecoveryProbeInvalidInput;

    memset(after, 0, sizeof(*after));
    /* Verify the complete plan before the first mutation. A stale plan must
     * be regenerated from a fresh ownership graph. */
    for (i = 0; i < plan->BitmapEditCount; ++i) {
        const UDFS_RECOVERY_SECTOR_EDIT *edit = &plan->BitmapEdits[i];
        if (edit->Lba >= reader->SectorCount ||
            edit->Lba == plan->LvidEdit.Lba ||
            RecoveryDifference(edit->Before, edit->After,
                   UDFS_RECOVERY_SECTOR_SIZE) == 0)
            return UdfsRecoveryProbeInvalidInput;
        for (j = 0; j < i; ++j)
            if (edit->Lba == plan->BitmapEdits[j].Lba)
                return UdfsRecoveryProbeInvalidInput;
        status = ReadSector(reader, after, edit->Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, edit->Before,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeCorrupt;
    }
    for (i = 0; i < plan->FeEditCount; ++i) {
        const UDFS_RECOVERY_SECTOR_EDIT *edit = &plan->FeEdits[i];
        uint16_t kind = Read16(edit->Before);
        if (edit->Lba >= reader->SectorCount ||
            edit->Lba == plan->LvidEdit.Lba ||
            (kind != 261 && kind != 266) ||
            ValidateTag(edit->Before, kind,
                Read32(edit->Before + 12)) !=
                    UdfsRecoveryProbeValidLayout ||
            ValidateTag(edit->After, kind,
                Read32(edit->Before + 12)) !=
                    UdfsRecoveryProbeValidLayout ||
            !DirectoryFePairDiffersOnlyInLinkCount(
                edit->Before, edit->After,
                Read32(edit->Before + 12)))
            return UdfsRecoveryProbeInvalidInput;
        for (j = 0; j < plan->BitmapEditCount; ++j)
            if (edit->Lba == plan->BitmapEdits[j].Lba)
                return UdfsRecoveryProbeInvalidInput;
        for (j = 0; j < i; ++j)
            if (edit->Lba == plan->FeEdits[j].Lba)
                return UdfsRecoveryProbeInvalidInput;
        status = ReadSector(reader, after, edit->Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, edit->Before,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeCorrupt;
    }
    if (plan->FidEditCount) {
        const UDFS_RECOVERY_SECTOR_EDIT *edit = &plan->FidEdit;
        int liveOnMirror;
        uint32_t child, recordOffset;
        if (edit->Lba >= reader->SectorCount ||
            plan->FidLiveLba >= reader->SectorCount ||
            edit->Lba == plan->FidLiveLba ||
            edit->Lba == plan->LvidEdit.Lba ||
            !DirectoryFidPairLiveDeleted(
                edit->Before, edit->After,
                plan->FidEditLogicalLbn,
                &liveOnMirror, &child, &recordOffset) ||
            liveOnMirror != 1)
            return UdfsRecoveryProbeInvalidInput;
        for (j = 0; j < plan->BitmapEditCount; ++j)
            if (edit->Lba == plan->BitmapEdits[j].Lba ||
                plan->FidLiveLba ==
                    plan->BitmapEdits[j].Lba)
                return UdfsRecoveryProbeInvalidInput;
        for (j = 0; j < plan->FeEditCount; ++j)
            if (edit->Lba == plan->FeEdits[j].Lba ||
                plan->FidLiveLba == plan->FeEdits[j].Lba)
                return UdfsRecoveryProbeInvalidInput;
        status = ReadSector(reader, after, edit->Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, edit->Before,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeCorrupt;
        status = ReadSector(reader, after, plan->FidLiveLba,
                            sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, edit->After,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeCorrupt;
    }
    status = ReadSector(reader, after, plan->LvidEdit.Lba, sector);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (RecoveryDifference(sector, plan->LvidEdit.Before,
               UDFS_RECOVERY_SECTOR_SIZE) != 0)
        return UdfsRecoveryProbeCorrupt;

    /* A split tombstone never commits the delete: restore the valid live
     * FID first.  All later states then retain a reachable child whose
     * pre-freed bit and parent count can be reconciled on retry. */
    if (plan->FidEditCount) {
        if (reader->WriteSector(reader->Context,
                                plan->FidEdit.Lba,
                                plan->FidEdit.After) != 0 ||
            reader->Flush(reader->Context) != 0)
            return UdfsRecoveryProbeIoError;
        status = ReadSector(reader, after,
                            plan->FidEdit.Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, plan->FidEdit.After,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeIoError;
    }
    /* Repair the parent's link count while the child's pre-free bit is still
     * present. That bit is the evidence needed to retry an interrupted FE
     * repair; clearing it first would leave an unexplained low link count.
     * An OPEN LVID blocks allocation throughout this recovery sequence. */
    for (i = 0; i < plan->FeEditCount; ++i)
        if (reader->WriteSector(reader->Context,
                                plan->FeEdits[i].Lba,
                                plan->FeEdits[i].After) != 0)
            return UdfsRecoveryProbeIoError;
    if (plan->FeEditCount && reader->Flush(reader->Context) != 0)
        return UdfsRecoveryProbeIoError;
    for (i = 0; i < plan->FeEditCount; ++i) {
        status = ReadSector(reader, after, plan->FeEdits[i].Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, plan->FeEdits[i].After,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeIoError;
    }
    for (i = 0; i < plan->BitmapEditCount; ++i)
        if (reader->WriteSector(reader->Context,
                                plan->BitmapEdits[i].Lba,
                                plan->BitmapEdits[i].After) != 0)
            return UdfsRecoveryProbeIoError;
    /* Flush is required even for zero bitmap edits: a prior interrupted
     * attempt may have left the newly allocated bits in a device cache. */
    if (reader->Flush(reader->Context) != 0)
        return UdfsRecoveryProbeIoError;
    for (i = 0; i < plan->BitmapEditCount; ++i) {
        status = ReadSector(reader, after,
                            plan->BitmapEdits[i].Lba, sector);
        if (status != UdfsRecoveryProbeValidLayout) return status;
        if (RecoveryDifference(sector, plan->BitmapEdits[i].After,
                   UDFS_RECOVERY_SECTOR_SIZE) != 0)
            return UdfsRecoveryProbeIoError;
    }

    /* Bitmap writes must be durable AND the entire owner graph must close
     * before publishing CLOSED. Check the planned aggregate values against a
     * new OPEN probe, including file/directory counts and the ID high-water
     * mark. Interrupted bitmap batches remain OPEN and can be replanned. */
    status = UdfsRecoveryProbeLayout(reader, after);
    if ((status != UdfsRecoveryProbeValidLayout &&
         status != UdfsRecoveryProbeLvidMismatch) ||
        !GraphCanRecover(after) || !after->CompleteOwnershipGraph ||
        after->PrevailingLvidLba != plan->LvidEdit.Lba ||
        after->PhysicalFreeBlocks != Read32(plan->LvidEdit.After + 80) ||
        after->MetadataFreeBlocks != Read32(plan->LvidEdit.After + 84) ||
        after->PartitionBlocks != Read32(plan->LvidEdit.After + 88) ||
        after->MetadataBlocks != Read32(plan->LvidEdit.After + 92) ||
        after->FilesVisited != Read32(plan->LvidEdit.After + 128) ||
        after->DirectoriesVisited != Read32(plan->LvidEdit.After + 132) ||
        after->MaxUniqueId >= Read64(plan->LvidEdit.After + 40))
        return status == UdfsRecoveryProbeValidLayout ||
               status == UdfsRecoveryProbeLvidMismatch ?
               UdfsRecoveryProbeCorrupt : status;

    status = ReadSector(reader, after, plan->LvidEdit.Lba, sector);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (RecoveryDifference(sector, plan->LvidEdit.Before,
               UDFS_RECOVERY_SECTOR_SIZE) != 0)
        return UdfsRecoveryProbeCorrupt;
    if (reader->WriteSector(reader->Context, plan->LvidEdit.Lba,
                            plan->LvidEdit.After) != 0 ||
        reader->Flush(reader->Context) != 0)
        return UdfsRecoveryProbeIoError;
    status = ReadSector(reader, after, plan->LvidEdit.Lba, sector);
    if (status != UdfsRecoveryProbeValidLayout) return status;
    if (RecoveryDifference(sector, plan->LvidEdit.After,
               UDFS_RECOVERY_SECTOR_SIZE) != 0)
        return UdfsRecoveryProbeIoError;

    status = UdfsRecoveryProbeLayout(reader, after);
    if (status != UdfsRecoveryProbeValidLayout ||
        !after->CompleteOwnershipGraph || !after->LvidCountersMatch ||
        after->LvidIntegrityType != 1 || after->WritableMountAuthorized)
        return status == UdfsRecoveryProbeValidLayout ?
               UdfsRecoveryProbeCorrupt : status;
    return UdfsRecoveryProbeValidLayout;
}
