#include <ntddk.h>
#define BYTE(num, b) (((num) >> b * 8) & 0xff)

__int64 __readmsr(int);
unsigned __int64 __readcr0(void);
void __writecr0(unsigned __int64 Data);
void _disable(void);
void _enable(void);

typedef struct _SYSTEM_SERVICE_TABLE {
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, * PSYSTEM_SERVICE_TABLE;