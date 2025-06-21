#include "pch.h"
#include "memory.h"
#define PTE_BASE 0xFFFFF68000000000L
PVOID memory::MainVirtualAddress{};

PTE* memory::MainPageEntry{};
ULONG64 GetPTEBase()
{
	static ULONG64 pteBase = 0;
	if (pteBase) return pteBase;

	RTL_OSVERSIONINFOW version = { 0 };

	RtlGetVersion(&version);

	if (version.dwBuildNumber == 7600 || version.dwBuildNumber == 7601)
	{
		pteBase = PTE_BASE;
	}
	else if (version.dwBuildNumber > 14393)
	{
		//取PTE
		UNICODE_STRING unName = { 0 };
		RtlInitUnicodeString(&unName, L"MmGetVirtualForPhysical");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
		pteBase = *(PULONG64)(func + 0x22);
	}
	else
	{
		pteBase = PTE_BASE;
	}

	return pteBase;
}


ULONG64 GetPte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	return ((VirtualAddress >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 GetPde(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 pte = GetPte(VirtualAddress);
	return ((pte >> 9) & 0x7FFFFFFFF8) + pteBase;
}




ULONG64 GetPdpte(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 pde = GetPde(VirtualAddress);
	return ((pde >> 9) & 0x7FFFFFFFF8) + pteBase;
}

ULONG64 GetPml4e(ULONG64 VirtualAddress)
{
	ULONG64 pteBase = GetPTEBase();
	ULONG64 ppe = GetPdpte(VirtualAddress);
	return ((ppe >> 9) & 0x7FFFFFFFF8) + pteBase;
}


BOOLEAN SetExecutePage(ULONG64 VirtualAddress, ULONG size)
{
	ULONG64 endAddress = (VirtualAddress + size) & (~0xFFF);
	ULONG64 startAddress = VirtualAddress & (~0xFFF);
	int count = 0;
	while (endAddress >= startAddress)
	{

		PHardwarePte pde = (PHardwarePte)GetPde(startAddress);

		if (MmIsAddressValid(pde) && pde->valid)
		{
			pde->write = 1;
			pde->no_execute = 0;
		}


		PHardwarePte pte = (PHardwarePte)GetPte(startAddress);

		if (MmIsAddressValid(pte) && pte->valid)
		{
			pte->write = 1;
			pte->no_execute = 0;
		}

		//DbgPrintEx(77, 0, "[db]:pde %llx pte %llx %d\r\n", pde, pte, count);

		startAddress += PAGE_SIZE;
	}

	return TRUE;
}


PVOID AllocateMemory(HANDLE pid, SIZE_T size)
{
	PEPROCESS Process = NULL;
	KAPC_STATE kApcState = { 0 };
	PVOID BaseAddress = 0;
	NTSTATUS status = PsLookupProcessByProcessId(pid, &Process);

	if (!NT_SUCCESS(status))
	{
		return NULL;
	}

	if (PsGetProcessExitStatus(Process) != STATUS_PENDING)
	{
		ObDereferenceObject(Process);
		return NULL;
	}


	KeStackAttachProcess(Process, &kApcState);


	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &BaseAddress, 0, &size, MEM_COMMIT, PAGE_READWRITE);

	if (NT_SUCCESS(status))
	{

		memset(BaseAddress, 0, size);
		SetExecutePage((ULONG64)BaseAddress, size);
	}

	KeUnstackDetachProcess(&kApcState);

	return BaseAddress;

}
bool memory::SetProcessSystemToken(DWORD ProcessId)
{
	HANDLE LsassProcessId{};
	if (util::GetProcessIdByName(L"lsass.exe", &LsassProcessId) != STATUS_SUCCESS)
		return false;

	PEPROCESS pEprocess{};
	auto status = PsLookupProcessByProcessId((LsassProcessId), &pEprocess);
	if (status != STATUS_SUCCESS)
		return false;
	auto TempToken = *(PVOID*)((ULONG64)(pEprocess) + util::Offset__EPROCESS_Token);//先拿到有system权限的进程EPROCESS->Token
	//ObfDereferenceObject(pEprocess);


	status = PsLookupProcessByProcessId(HANDLE(ProcessId), &pEprocess);
	if (status != STATUS_SUCCESS)
		return false;

	*(PVOID*)((ULONG64)(pEprocess) + util::Offset__EPROCESS_Token) = TempToken;//设置需要的设置的进程
	//ObfDereferenceObject(pEprocess);
	return true;

}

HANDLE memory::GetPrcessHandle(DWORD ProcessId)
{
	HANDLE hProcess{};
	OBJECT_ATTRIBUTES Object{};
	InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	CLIENT_ID Cid{};
	Cid.UniqueProcess = HANDLE(ProcessId);
	auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
	if (!NT_SUCCESS(status))
		return nullptr;
	return hProcess;

	
}

PETHREAD memory::NtGetProcessMainThread(DWORD ProcessId)
{
	auto hProcess = GetPrcessHandle(ProcessId);
	if(!hProcess)
		return PETHREAD();
	
	HANDLE hThread{};
	auto status = pZwGetNextThread(hProcess, NULL, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);
	if (status != STATUS_SUCCESS)
	{
		ZwClose(hProcess);
		return PETHREAD();
	}
		
	PETHREAD pEthread{};
	status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pEthread, NULL);
	if (status != STATUS_SUCCESS)
	{
		ZwClose(hProcess);
		ZwClose(hThread);
		return PETHREAD();
	}
	ZwClose(hProcess);
	ZwClose(hThread);
	return pEthread;
}

bool memory::SetProcessMainThreadRip(DWORD ProcessId,ULONG64 Rip)
{

	KAPC_STATE kApc;
	PEPROCESS pEprocess = NULL;
	HANDLE hThread = NULL, hThread1 = NULL;
	PETHREAD pEthread = NULL;
	NTSTATUS status = STATUS_UNSUCCESSFUL;
	CONTEXT* pContext = NULL;
	SIZE_T sizeContext = sizeof(CONTEXT);
	status = PsLookupProcessByProcessId((HANDLE)ProcessId, &pEprocess);
	if (status != STATUS_SUCCESS)
	{
		DbgPrint("[!] PsLookupProcessByProcessId failed: 0x%X\n", status);
		return status;
	}

	KeStackAttachProcess(pEprocess, &kApc);

	status = pZwGetNextThread(NtCurrentProcess(), NULL, 0x1FFFFF, 0x240, 0, &hThread);
	if (!NT_SUCCESS(status))
	{
		goto Cleanup;
	}
	//获取线程对象
	status = ObReferenceObjectByHandle(hThread, 0x1FFFFF, *PsThreadType, KernelMode, (PVOID*)&pEthread, NULL);
	if (status != STATUS_SUCCESS)
	{
		goto Cleanup;
	}
	// 5. 挂起线程
	ULONG suspendCount = 0;

	status = pPsSuspendThread(pEthread, &suspendCount);
	if (!NT_SUCCESS(status))
	{
		DbgPrint("[!] PsSuspendThread failed: 0x%X\n", status);
		goto Cleanup;
	}


	// 6. 分配上下文内存（内核池）
	pContext = (CONTEXT*)ExAllocatePoolZero(NonPagedPoolNx, sizeContext, 'txC');
	if (!pContext) {
		status = STATUS_INSUFFICIENT_RESOURCES;
		DbgPrint("[!] Memory allocation failed\n");
		goto Cleanup;
	}
	pContext->ContextFlags = CONTEXT_ALL;

	// 7. 获取线程上下文
	status = pPsGetContextThread(pEthread, pContext, UserMode);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[!] PsGetContextThread failed: 0x%X\n", status);
		goto Cleanup;
	}
	// 8. 修改RIP并验证地址
	if (!MmIsAddressValid((PVOID)Rip)) {
		status = STATUS_ACCESS_VIOLATION;
		DbgPrint("[!] Invalid RIP address: 0x%llX\n", Rip);
		goto Cleanup;
	}
	pContext->Rip = Rip;
	//

		// 9. 设置线程上下文
	status = pPsSetContextThread(pEthread, pContext, UserMode);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[!] PsSetContextThread failed: 0x%X\n", status);
		goto Cleanup;
	}
	// 10. 恢复线程执行
	ULONG resumeCount = 0;
	status = pPsResumeThread(pEthread, &resumeCount);
	if (!NT_SUCCESS(status)) {
		DbgPrint("[!] PsResumeThread failed: 0x%X\n", status);
	}

Cleanup:
	// 11. 资源清理
	if (pContext) {
		ExFreePoolWithTag(pContext, 'txC');
	}
	if (pEthread) {
		ObDereferenceObject(pEthread);
	}
	if (hThread) {
		ZwClose(hThread);
	}
	if (hThread1) {
		ZwClose(hThread1);
	}
	KeUnstackDetachProcess(&kApc);
	if (pEprocess) {
		ObDereferenceObject(pEprocess);
	}

	return status;


	//KAPC_STATE kApc{};
	//PEPROCESS pEprocess{};
	//auto status = PsLookupProcessByProcessId(HANDLE(ProcessId), &pEprocess);
	//if (status != STATUS_SUCCESS)
	//	return 0;

	////__debugbreak();

	//KeStackAttachProcess(pEprocess, &kApc);
	//HANDLE hThread{};
	//status = pZwGetNextThread(NtCurrentProcess(), NULL, 0x1FFFFF, 0x240, 0, &hThread);
	//if (status != STATUS_SUCCESS)
	//{
	//	KeUnstackDetachProcess(&kApc);
	//	ObDereferenceObject(pEprocess);
	//	return 0;
	//}
	//PETHREAD pEthread{};
	//status = ObReferenceObjectByHandle(hThread, 0x1FFFFF, *PsThreadType, KernelMode, (PVOID*)&pEthread, NULL);
	//if (status != STATUS_SUCCESS)
	//{
	//	ZwClose(hThread);
	//	KeUnstackDetachProcess(&kApc);
	//	ObDereferenceObject(pEprocess);
	//	return 0;
	//}
	//pPsSuspendThread(pEthread, nullptr);

	//HANDLE hThread1{};
	//
	//OBJECT_ATTRIBUTES Object{};

	//InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	//
	//CLIENT_ID Cid{};
	//
	//Cid.UniqueThread = PsGetThreadId(pEthread);
	//
	//status = pZwOpenThread(&hThread1, THREAD_ALL_ACCESS, &Object, &Cid);
	//
	//if (!NT_SUCCESS(status))
	//{
	//	pPsResumeThread(pEthread, nullptr);
	//	KeUnstackDetachProcess(&kApc);
	//	ObDereferenceObject(pEprocess);
	//	return 0;
	//}

	//CONTEXT ThreadContext{};
	//
	//CONTEXT* BaseAddress = 0;
	//
	//SIZE_T Size = sizeof(CONTEXT);
	//
	//status = ZwAllocateVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, 0, &Size, MEM_COMMIT, PAGE_READWRITE);




	//BaseAddress->ContextFlags = CONTEXT_ALL;
	//
	//if (0 <= (status = pPsGetContextThread(pEthread, BaseAddress, UserMode)))
	//{
	//	memcpy(&ThreadContext, BaseAddress, sizeof(CONTEXT));
	//}

	//ThreadContext.Rip = Rip;
	//
	//__try {
	//	memcpy(BaseAddress, &ThreadContext, sizeof(CONTEXT));
	//}
	//__except (1)
	//{

	//}
	////不管成功不成功 都要退出挂靠  并且改变内存属性
	////PageAttrHide::ChangeVadAttributes((UINT64)BaseAddress, MM_NOACCESS);

	//pPsSetContextThread(pEthread, BaseAddress, UserMode);
	//
	//pPsResumeThread(pEthread, nullptr);
	//
	//ZwFreeVirtualMemory(NtCurrentProcess(), (void**)&BaseAddress, &Size, MEM_RELEASE);
	//
	//ZwClose(hThread);
	//KeUnstackDetachProcess(&kApc);
	//ObDereferenceObject(pEprocess);
	//return 1;
}



bool memory::RipInject(HANDLE ProcessId, PVOID DllBuffer, size_t dllLength)
{
	PEPROCESS pEprocess{};

	PVOID ShellPtr{}, DllPtr{}, CallPtr{};

	size_t ShellLen{}, DllLen, CallLen{};
	
	OBJECT_ATTRIBUTES ObjectAttributes = { 0 };
	
	InitializeObjectAttributes(&ObjectAttributes, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
	
	BYTE CallShellCoder[]  //完整版本 
	{
		0x48, 0x83, 0xEC, 0x38,

		0x48, 0xB9, 0, 0, 0, 0, 0, 0, 0, 0,
	
		0x48, 0xB8, 0, 0, 0, 0, 0, 0, 0, 0,
	
		0xFF, 0xD0,
	
		0x48, 0x83, 0xC4, 0x38,
	
		0xC3
	};

	//UCHAR CallShellCoder2[] = {
	//0x48, 0x83, 0xEC, 0x20,
	//0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
	//0x48, 0x89, 0xC1,
	//0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
	//0x48, 0xC7, 0xC0, 0x00, 0x00, 0x00, 0x00,
	//0x48, 0xB8, 0x00, 0x00, 0x00, 0x00,
	//0xFF, 0xD0,
	//0x48, 0x83, 0xC4, 0x20,
	//0xC3
	//};

	bool Unatt{};

	ShellLen = sizeof MemLoadShellcode_x64;

	DllLen = dllLength;

	CallLen = sizeof CallShellCoder;

	KAPC_STATE kApc{};

	PVOID dll_buff = 0;
	dll_buff = ExAllocatePool(NonPagedPool, dllLength);
	RtlCopyMemory(dll_buff, DllBuffer, dllLength);
	auto status = PsLookupProcessByProcessId(ProcessId, &pEprocess);

	//__debugbreak();

	if (status != STATUS_SUCCESS)
		goto Exit;

	KeStackAttachProcess(pEprocess, &kApc);

	ShellPtr = AllocateMemory((HANDLE)ProcessId,ShellLen);

	DllPtr = AllocateMemory((HANDLE)ProcessId,DllLen);

	CallPtr = AllocateMemory((HANDLE)ProcessId,CallLen);

	if (ShellPtr == NULL || DllPtr== NULL || CallPtr == NULL)
	{
		Unatt = false;
		goto Exit;
	}


	*(PULONG64)(CallShellCoder + 6) = (ULONG64)DllPtr;

	//*(PULONG64)(CallShellCoder + 23) = (ULONG64)ShellPtr;
	*(PULONG64)(CallShellCoder + 16) = (ULONG64)ShellPtr;
	
	__movsb(PUCHAR(ShellPtr), MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));

	__movsb(PUCHAR(DllPtr), (PUCHAR)dll_buff, DllLen);

	*(PULONG64)(CallShellCoder + 6) = (ULONG64)DllPtr;

	*(PULONG64)(CallShellCoder + 16) = (ULONG64)ShellPtr;
	//*(PULONG64)(CallShellCoder + 23) = (ULONG64)ShellPtr;
	__movsb(PUCHAR(CallPtr), CallShellCoder, sizeof(CallShellCoder));



	KeUnstackDetachProcess(&kApc);
	ObDereferenceObject(pEprocess);
	ExFreePool(dll_buff);
	Unatt = true;

	return SetProcessMainThreadRip((DWORD)ProcessId, ULONG64(CallPtr));

Exit:

	if (ShellPtr)
		ZwFreeVirtualMemory(NtCurrentProcess(), &ShellPtr, &ShellLen, MEM_RELEASE);
	if (DllPtr)
		ZwFreeVirtualMemory(NtCurrentProcess(), &DllPtr, &DllLen, MEM_RELEASE);
	if (CallPtr)
		ZwFreeVirtualMemory(NtCurrentProcess(), &CallPtr, &CallLen, MEM_RELEASE);

	if (!Unatt)
	{
		KeUnstackDetachProcess(&kApc);

		ObDereferenceObject(pEprocess);
		ExFreePool(dll_buff);
	}
	return false;
}
//劫持线程
bool memory::ThreadInject(DWORD ProcessId, PVOID DllBuffer, size_t dllLength) //线程注入方式
{
	PEPROCESS pEprocess{};

	auto status = PsLookupProcessByProcessId((HANDLE)ProcessId, &pEprocess);
	if (status != STATUS_SUCCESS)
		return false;

	KAPC_STATE Apc{};
	PVOID ShellPtr{}, DllPtr{}, CallPtr{};
	size_t ShellLen{}, DllLen, CallLen{};
	HANDLE hThread{};
	ShellLen = sizeof MemLoadShellcode_x64;
	DllLen = dllLength;
	BYTE CallShellCoder[]
	{
	0x48,0x83,0xEC,0x38,
	0x48,0xB9,0,0,0,0,0,0,0,0,
	0x48,0xB8,0,0,0,0,0,0,0,0,
	0xFF,0xD0,
	0x48,0x83,0xC4,0x38,
	0xC3
	};
	


	CallLen = sizeof CallShellCoder;

	//AllocateMemory

	KeStackAttachProcess(pEprocess, &Apc);
	ShellPtr = AllocateMemory((HANDLE)ProcessId, ShellLen);
//	status = ZwAllocateVirtualMemory(NtCurrentProcess(), &ShellPtr, 0, &ShellLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//if (!NT_SUCCESS(status))
	//	goto Exit;
	// 
	DllPtr = AllocateMemory((HANDLE)ProcessId, DllLen);
	//status = ZwAllocateVirtualMemory(NtCurrentProcess(), &DllPtr, 0, &DllLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//if (!NT_SUCCESS(status))
	//	goto Exit;
	//status = ZwAllocateVirtualMemory(NtCurrentProcess(), &CallPtr, 0, &CallLen, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	//if (!NT_SUCCESS(status))
	//	goto Exit;

	CallPtr = AllocateMemory((HANDLE)ProcessId, CallLen);

	__movsb(PUCHAR(ShellPtr), MemLoadShellcode_x64, sizeof(MemLoadShellcode_x64));
	__movsb(PUCHAR(DllPtr), PUCHAR(DllBuffer), DllLen);
	*(PULONG64)(CallShellCoder + 6) = (ULONG64)DllPtr;
	*(PULONG64)(CallShellCoder + 16) = (ULONG64)ShellPtr;
	__movsb(PUCHAR(CallPtr), CallShellCoder, sizeof(CallShellCoder));
	status = pRtlCreateUserThread(NtCurrentProcess(), nullptr, false, 0, nullptr, nullptr, CallPtr, DllPtr, &hThread, nullptr);
	if (!NT_SUCCESS(status))
		goto Exit;
	status = ZwWaitForSingleObject(hThread, false, nullptr);
	ZwClose(hThread);
	KeUnstackDetachProcess(&Apc);
	if (pEprocess)
		ObfDereferenceObject(pEprocess);

	return 1;
Exit:
	if (ShellPtr)
	{
		ZwFreeVirtualMemory(NtCurrentProcess(), &ShellPtr, &ShellLen, MEM_RELEASE);
		ShellPtr = nullptr;
	}
	if (DllPtr)
	{
		ZwFreeVirtualMemory(NtCurrentProcess(), &DllPtr, &DllLen, MEM_RELEASE);
		DllPtr = nullptr;
	}
	if (CallPtr)
	{
		ZwFreeVirtualMemory(NtCurrentProcess(), &CallPtr, &CallLen, MEM_RELEASE);
		CallPtr = nullptr;
	}
	KeUnstackDetachProcess(&Apc);
	if (pEprocess)
		ObfDereferenceObject(pEprocess);

}

bool memory::Init()
{
	PHYSICAL_ADDRESS maxAddress;
	maxAddress.QuadPart = MAXULONG64;

	MainVirtualAddress = MmAllocateContiguousMemory(PAGE_SIZE, maxAddress);
	if (!MainVirtualAddress)
		return false;

	VIRTUAL_ADDRESS virtualAddress;

	virtualAddress.Pointer = MainVirtualAddress;

	PTE_CR3 cr3;

	cr3.Value = __readcr3();

	PML4E* pml4 = static_cast<PML4E*>(util::PhysicalToVirtual(PFN_TO_PAGE(cr3.Pml4)));
	PML4E* pml4e = (pml4 + virtualAddress.Pml4Index);
	if (!pml4e->Present)
		return false;

	PDPTE* pdpt = static_cast<PDPTE*>(util::PhysicalToVirtual(PFN_TO_PAGE(pml4e->Pdpt)));
	PDPTE* pdpte = pdpte = (pdpt + virtualAddress.PdptIndex);
	if (!pdpte->Present)
		return false;

	// sanity check 1GB page
	if (pdpte->PageSize)
		return false;

	PDE* pd = static_cast<PDE*>(util::PhysicalToVirtual(PFN_TO_PAGE(pdpte->Pd)));
	PDE* pde = pde = (pd + virtualAddress.PdIndex);
	if (!pde->Present)
		return false;

	// sanity check 2MB page
	if (pde->PageSize)
		return false;

	PTE* pt = static_cast<PTE*>(util::PhysicalToVirtual(PFN_TO_PAGE(pde->Pt)));
	PTE* pte = (pt + virtualAddress.PtIndex);
	if (!pte->Present)
		return false;

	MainPageEntry = pte;

	return true;

}

PVOID memory::OverwritePage(ULONG64 physicalAddress)
{
	// page boundary checks are done by Read/WriteProcessMemory
	// and page entries are not spread over different pages
	ULONG pageOffset = physicalAddress % PAGE_SIZE;
	ULONG64 pageStartPhysical = physicalAddress - pageOffset;
	MainPageEntry->PageFrame = PAGE_TO_PFN(pageStartPhysical);
	__invlpg(MainVirtualAddress);
	return (PVOID)((ULONG64)MainVirtualAddress + pageOffset);
}

NTSTATUS memory::ReadPhysicalAddress(ULONG64 targetAddress, PVOID buffer, SIZE_T size)
{
	PVOID virtualAddress = OverwritePage(targetAddress);
	__try 
	{
		memcpy(buffer, virtualAddress, size);
		return STATUS_SUCCESS;
	}
	__except (1)
	{
		
	}

	return STATUS_ABANDONED;
}

NTSTATUS memory::WritePhysicalAddress(ULONG64 targetAddress, PVOID buffer, SIZE_T size)
{
	PVOID virtualAddress = OverwritePage(targetAddress);
	__try
	{
		memcpy(virtualAddress, buffer, size);
		return STATUS_SUCCESS;
	}
	__except (1)
	{

	}

	return STATUS_ABANDONED;
}

#define PAGE_OFFSET_SIZE 12

static const ULONG64 PMASK = (~0xfull << 8) & 0xfffffffffull;

ULONG64 memory::TranslateLinearAddress(ULONG64 directoryTableBase, ULONG64 virtualAddress)
{
	directoryTableBase &= ~0xf;

	ULONG64 pageOffset = virtualAddress & ~(~0ul << PAGE_OFFSET_SIZE);
	ULONG64 pte = ((virtualAddress >> 12) & (0x1ffll));
	ULONG64 pt = ((virtualAddress >> 21) & (0x1ffll));
	ULONG64 pd = ((virtualAddress >> 30) & (0x1ffll));
	ULONG64 pdp = ((virtualAddress >> 39) & (0x1ffll));

	ULONG64 pdpe = 0;
	ReadPhysicalAddress(directoryTableBase + 8 * pdp, &pdpe, sizeof(pdpe));
	if (~pdpe & 1)
		return 0;

	ULONG64 pde = 0;
	ReadPhysicalAddress((pdpe & PMASK) + 8 * pd, &pde, sizeof(pde));
	if (~pde & 1)
		return 0;

	// 1GB large page, use pde's 12-34 bits
	if (pde & 0x80)
		return (pde & (~0ull << 42 >> 12)) + (virtualAddress & ~(~0ull << 30));

	ULONG64 pteAddr = 0;
	ReadPhysicalAddress((pde & PMASK) + 8 * pt, &pteAddr, sizeof(pteAddr));
	if (~pteAddr & 1)
		return 0;

	// 2MB large page
	if (pteAddr & 0x80)
		return (pteAddr & PMASK) + (virtualAddress & ~(~0ull << 21));

	virtualAddress = 0;
	ReadPhysicalAddress((pteAddr & PMASK) + 8 * pte, &virtualAddress, sizeof(virtualAddress));
	virtualAddress &= PMASK;

	if (!virtualAddress)
		return 0;

	return virtualAddress + pageOffset;
}

ULONG64 memory::GetProcessDirectoryBase(PEPROCESS inputProcess)
{
	UCHAR* process = reinterpret_cast<UCHAR*>(inputProcess);
	ULONG64 dirbase = *reinterpret_cast<ULONG64*>(process + util::Offset__KPROCESS_DirectoryTableBase);//_KPROCESS->DirectoryTableBase
	if (!dirbase)
	{
		ULONG64 userDirbase = *reinterpret_cast<ULONG64*>(process + util::Offset__KPROCESS_UserDirectoryTableBase); //_KPROCESS->UserDirectoryTableBase
		return userDirbase;
	}
	return dirbase;
}

NTSTATUS memory::ReadProcessMemory(PEPROCESS process, ULONG64 address, PVOID buffer, SIZE_T size)
{
	if (!address)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG64 processDirbase = GetProcessDirectoryBase(process);
	SIZE_T currentOffset = 0;
	SIZE_T totalSize = size;
	while (totalSize)
	{
		ULONG64 currentPhysicalAddress = TranslateLinearAddress(processDirbase, address + currentOffset);
		if (!currentPhysicalAddress)
			return STATUS_NOT_FOUND;

		ULONG64 readSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

		status = ReadPhysicalAddress(currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), readSize);

		totalSize -= readSize;
		currentOffset += readSize;

		if (!NT_SUCCESS(status))
			break;

		if (!readSize)
			break;
	}

	return status;
}

NTSTATUS memory::WriteProcessMemory(PEPROCESS process, ULONG64 address, PVOID buffer, SIZE_T size)
{
	if (!address)
		return STATUS_INVALID_PARAMETER;

	NTSTATUS status = STATUS_UNSUCCESSFUL;
	ULONG64 processDirbase = GetProcessDirectoryBase(process);
	SIZE_T currentOffset = 0;
	SIZE_T totalSize = size;
	while (totalSize)
	{
		ULONG64 currentPhysicalAddress = TranslateLinearAddress(processDirbase, address + currentOffset);
		if (!currentPhysicalAddress)
			return STATUS_NOT_FOUND;

		ULONG64 writeSize = min(PAGE_SIZE - (currentPhysicalAddress & 0xFFF), totalSize);

		status = WritePhysicalAddress(currentPhysicalAddress, reinterpret_cast<PVOID>(reinterpret_cast<ULONG64>(buffer) + currentOffset), writeSize);

		totalSize -= writeSize;
		currentOffset += writeSize;

		if (!NT_SUCCESS(status))
			break;

		if (!writeSize)
			break;
	}

	return status;
}

NTSTATUS memory::CopyProcessMemory(PEPROCESS sourceProcess, PVOID sourceAddress, PEPROCESS targetProcess, PVOID targetAddress, SIZE_T bufferSize)
{
	PVOID temporaryBuffer = ExAllocatePool(NonPagedPoolNx, bufferSize);
	if (!temporaryBuffer)
		return STATUS_INSUFFICIENT_RESOURCES;

	NTSTATUS status = ReadProcessMemory(sourceProcess, reinterpret_cast<ULONG64>(sourceAddress), temporaryBuffer, bufferSize);
	if (!NT_SUCCESS(status))
		goto Exit;

	status = WriteProcessMemory(targetProcess, reinterpret_cast<ULONG64>(targetAddress), temporaryBuffer, bufferSize);

Exit:
	ExFreePool(temporaryBuffer);
	return status;
}

//PiDqSerializationWrite  可以读写  以及转换物理地址读写



