PUBLIC a_handle
EXTRN Handle : PROC

.code _text

a_handle PROC PUBLIC

;int 3
mov rcx, [rsp+48h] ; get arguments
mov rdx, [rsp+50h]
sub rsp, 28h ; allocate more space for function for protect stack
call Handle
add rsp, 28h
pop r15

jmp exit

a_handle ENDP

exit:
	mov r11, rsp ; execute NtTerminateProcess overwrite instructions
	mov qword ptr [r11+18h], rbx
	mov dword ptr [rsp+10h], edx
	push rbp
	push rsi

	push r15
	xor r15, r15
	ret

END  