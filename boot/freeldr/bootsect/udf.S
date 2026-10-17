/* ReactOS UDF 2.50 BIOS VBR. BIOS/MBR loads this sector at 0000:7C00.
 * The installer fills the UDFSRAW1 record from FREELDR.SYS's UDF allocation
 * descriptor. This boot path requires a single contiguous data extent.
 */
#include <asm.inc>

.code16
start:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, HEX(7c00)
    mov ds, ax
    mov es, ax
    sti
    mov byte ptr [boot_drive], dl

    mov bx, HEX(55aa)
    mov ah, HEX(41)
    int HEX(13)
    jc disk_error
    cmp bx, HEX(aa55)
    jne disk_error
    test cx, 1
    jz disk_error

    cmp dword ptr [boot_parameters + 8], 0
    jz disk_error
    cmp word ptr [boot_parameters + 12], 0
    jz disk_error
    mov ax, word ptr [boot_parameters + 12]
    mov word ptr [remaining], ax
    mov eax, dword ptr [boot_parameters + 8]
    mov dword ptr [dap_lba], eax
    mov word ptr [dap_segment], HEX(0f80)

read_next:
    cmp word ptr [remaining], 0
    je boot_freeldr
    mov si, offset dap
    mov dl, byte ptr [boot_drive]
    mov ah, HEX(42)
    int HEX(13)
    jc disk_error
    add word ptr [dap_segment], HEX(20)
    inc dword ptr [dap_lba]
    dec word ptr [remaining]
    jmp read_next

boot_freeldr:
    mov dl, byte ptr [boot_drive]
    xor dh, dh
    ljmp16 HEX(0f80), 0

disk_error:
    mov si, offset message
print_next:
    lodsb
    test al, al
    jz halt
    mov ah, HEX(0e)
    mov bx, 7
    int HEX(10)
    jmp print_next
halt:
    hlt
    jmp halt

message:
    .asciz "UDF boot read error"
boot_drive:
    .byte 0
remaining:
    .word 0
dap:
    .byte 16, 0
    .word 1
    .word 0
dap_segment:
    .word HEX(0f80)
dap_lba:
    .long 0
    .long 0

/* Patchable boot record: magic, absolute disk LBA, 512-byte sector count. */
boot_parameters:
    .ascii "UDFSRAW1"
    .long 0
    .word 0

.org 510
.word HEX(aa55)
.endcode16

END
