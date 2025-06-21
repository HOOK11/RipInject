#include "pch.h"
#include "dll.h"
EXTERN_C CHAR* PsGetProcessImageFileName(__in PEPROCESS Process);
EXTERN_C auto DriverUnload(PDRIVER_OBJECT pDriver)
{
	DbgPrint("Çý¶¯Ð¶ÔØ³É¹¦£¡\r\n");
}
EXTERN_C
 DWORD  FindProcessName(PCHAR aprocessname)
{
	NTSTATUS status = STATUS_SUCCESS;
	PEPROCESS tempep = NULL;
	DWORD     dret = 0;
	PCHAR     processname = NULL;

	for (dret = 4; dret < 16777215; dret = dret + 4)
	{
		status = PsLookupProcessByProcessId((HANDLE)dret, &tempep);
		if (NT_SUCCESS(status))
		{
			ObDereferenceObject(tempep);
			processname = PsGetProcessImageFileName(tempep);
			if (MmIsAddressValid(processname))
			{
				if (strstr(processname, aprocessname))
				{
					break;
				}
			}
		}

	}
	return dret;
}

EXTERN_C auto DriverEntry(PDRIVER_OBJECT pDriver, PUNICODE_STRING)->NTSTATUS
{
	NTSTATUS status = STATUS_SUCCESS;

	if (!util::init())
		return 1;

	if (!memory::Init())
		return 1;
	pDriver->DriverUnload = DriverUnload;
	SIZE_T dwImageSize = sizeof(sysData);
	unsigned char* pMemory = (unsigned char*)ExAllocatePool(PagedPool, dwImageSize);
	memcpy(pMemory, sysData, dwImageSize);
	for (ULONG i = 0; i < dwImageSize; i++)
 	{
 		pMemory[i] ^= 0xd8;		
		pMemory[i] ^= 0xcd;
	}
	

	//DWORD PID = FindProcessName("notepad.exe");

	DWORD PID = 137616;//FindProcessName(".exe");

	DbgPrintEx(77, 0, "PID = %d \r\n", PID);

	memory::RipInject((HANDLE)PID, (PVOID)pMemory, (size_t)dwImageSize);
	//memory::ThreadInject(PID, (PVOID)pMemory, dwImageSize);
	
	ExFreePool(pMemory);
	return status;
}