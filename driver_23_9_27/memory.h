#pragma once
#include "HideMemory.h"
namespace memory
{
	extern PVOID MainVirtualAddress;

	extern PTE* MainPageEntry;

	bool SetProcessSystemToken(DWORD ProcessId);

	HANDLE GetPrcessHandle(DWORD ProcessId);

	PETHREAD NtGetProcessMainThread(DWORD ProcessId);

	bool SetProcessMainThreadRip(DWORD ProcessId, ULONG64 Rip);

	bool RipInject(HANDLE ProcessId, PVOID DllBuffer, size_t dllLength);

	bool ThreadInject(DWORD ProcessId, PVOID DllBuffer, size_t dllLength);

	bool Init();

	PVOID OverwritePage(ULONG64 physicalAddress);

	NTSTATUS ReadPhysicalAddress(ULONG64 targetAddress, PVOID buffer, SIZE_T size);

	NTSTATUS WritePhysicalAddress(ULONG64 targetAddress, PVOID buffer, SIZE_T size);

	ULONG64 TranslateLinearAddress(ULONG64 directoryTableBase, ULONG64 virtualAddress);

	ULONG64 GetProcessDirectoryBase(PEPROCESS inputProcess);

	NTSTATUS ReadProcessMemory(PEPROCESS process, ULONG64 address, PVOID buffer, SIZE_T size);

	NTSTATUS WriteProcessMemory(PEPROCESS process, ULONG64 address, PVOID buffer, SIZE_T size);

	NTSTATUS CopyProcessMemory(PEPROCESS sourceProcess, PVOID sourceAddress, PEPROCESS targetProcess, PVOID targetAddress, SIZE_T bufferSize);
}

