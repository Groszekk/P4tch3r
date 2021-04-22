PUBLIC a_handle
EXTRN Handler : PROC

.code _text

a_handle PROC PUBLIC

sub rsp, 112h

push rax
push rbx
push rsi
push rdi
push rcx
push rdx
push r8
push r9
push r10
push r11
push r12
push r13
push r14

; rcx = handle
; rdx = exit code
call Handler

pop r14
pop r13
pop r12
pop r11
pop r10
pop r9
pop r8
pop rdx
pop rcx
pop rdi
pop rsi
pop rbx
pop rax

add rsp, 112h

pop r15
jmp exit

a_handle ENDP

getret PROC PUBLIC
pop r12
mov rbx, qword ptr [rsp+90h]
add rsp, 40h
push r12
;mov rax, 00000000C0000008h
ret

getret ENDP

exit:
	mov r11, rsp ; execute NtTerminateProcess overwrite instructions
	mov qword ptr [r11+18h], rbx
	mov dword ptr [rsp+10h], edx
	push rbp

	push r15
	xor r15, r15
	ret

END