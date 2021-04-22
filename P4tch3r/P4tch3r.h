#include <ntddk.h>
#define BYTE(num, b) (((num) >> b * 8) & 0xff)
//#define RELATIVE(wait) (-(wait))
//#define NANOSECONDS(nanos) \
//(((signed __int64)(nanos)) / 100L)
//
//#define MICROSECONDS(micros) \
//(((signed __int64)(micros)) * NANOSECONDS(1000L))
//
//#define MILLISECONDS(milli) \
//(((signed __int64)(milli)) * MICROSECONDS(1000L))
//
//#define SECONDS(seconds) \
//(((signed __int64)(seconds)) * MILLISECONDS(1000L))
//
//#define SEND CTL_CODE(FILE_DEVICE_UNKNOWN, 0x801, METHOD_BUFFERED, FILE_WRITE_DATA)
//#define RECIVE CTL_CODE(FILE_DEVICE_UNKNOWN, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

__int64 __readmsr(int);
unsigned __int64 __readcr0(void);
void __writecr0(unsigned __int64 Data);
void _disable(void);
void _enable(void);

typedef struct
{
	PVOID  		ServiceTableBase;
	PVOID  		ServiceCounterTableBase;
	ULONGLONG  	NumberOfServices;
	PVOID  		ParamTableBase;
} SYSTEM_SERVICE_TABLE, *PSYSTEM_SERVICE_TABLE;

typedef struct
{
	long long hProcess;
	int uExitCode;
} NtTerminateProcessArgs;