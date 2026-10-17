/* ReactOS UDF 2.50 BIOS VBR. BIOS/MBR loads this sector at 0000:7C00.
 * The installer fills the UDFSRAW1 record from FREELDR.SYS's UDF allocation
 * descriptor. This boot path requires a single contiguous data extent.
 */
.intel_syntax noprefix
.code16
.global start
start:
    cli
    xor ax, ax
    mov ss, ax
    mov sp, 0x7c00
    mov ds, ax
    mov es, ax
    sti
    mov byte ptr [boot_drive], dl

    mov bx, 0x55aa
    mov ah, 0x41
    int 0x13
    jc disk_error
    cmp bx, 0xaa55
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
    mov word ptr [dap_segment], 0x0f80

read_next:
    cmp word ptr [remaining], 0
    je boot_freeldr
    mov si, offset dap
    mov dl, byte ptr [boot_drive]
    mov ah, 0x42
    int 0x13
    jc disk_error
    add word ptr [dap_segment], 0x20
    inc dword ptr [dap_lba]
    dec word ptr [remaining]
    jmp read_next

boot_freeldr:
    mov dl, byte ptr [boot_drive]
    xor dh, dh
    ljmp 0x0f80, 0

disk_error:
    mov si, offset message
print_next:
    lodsb
    test al, al
    jz halt
    mov ah, 0x0e
    mov bx, 7
    int 0x10
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
    .word 0x0f80
dap_lba:
    .long 0
    .long 0

/* Patchable boot record: magic, absolute disk LBA, 512-byte sector count. */
boot_parameters:
    .ascii "UDFSRAW1"
    .long 0
    .word 0

.org 510
.word 0xaa55
