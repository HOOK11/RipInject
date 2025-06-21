#include <ntifs.h>
#include <ntddk.h>
#include <intrin.h>
#include "HideMemory.h"
#include "./hde/hde64.h"
#include<wdm.h>

using namespace PageAttrHide;

ULONG PageAttrHide::GetOsVersionNumber()
{

	RTL_OSVERSIONINFOW version = { 0 };

	NTSTATUS status = RtlGetVersion(&version);

	if (!NT_SUCCESS(status))
	{
		return 0;
	}

	return version.dwBuildNumber;
}



UINT64 GetMmPfnDataBase() {
	UINT64 RetAddr = 0;

	UNICODE_STRING usMmGetVirtualForPhysical = RTL_CONSTANT_STRING(L"MmGetVirtualForPhysical");


	PUCHAR pStartSearch = (PUCHAR)MmGetSystemRoutineAddress(&usMmGetVirtualForPhysical);

	if (!pStartSearch) {

		return RetAddr;
	}

	for (unsigned int i = 0; i < 0x50; i++) {

		if (*(pStartSearch + i) == 0x48 && *(pStartSearch + i + 1) == 0xB8) {

			RetAddr = *(PUINT64)(pStartSearch + i + 2);
			break;
		}
	}

	if (RetAddr == 0 || !MmIsAddressValid((PVOID)RetAddr)) {

		return 0;
	}

	return (UINT64)PAGE_ALIGN(RetAddr);
}

ULONG_PTR PageAttrHide::GetPteBase()
{
	static ULONG64 pte_base = NULL;
	if (pte_base) return pte_base;

	// 获取os版本
	ULONG64 versionNumber = 0;
	versionNumber = GetOsVersionNumber();

	// win7或者1607以下
	if (versionNumber == 7601 || versionNumber == 7600 || versionNumber < 14393)
	{
		pte_base = 0xFFFFF68000000000ull;
		return pte_base;
	}
	else // win10 1607以上
	{
		//取PTE（第一种）
		UNICODE_STRING unName = { 0 };
		RtlInitUnicodeString(&unName, L"MmGetVirtualForPhysical");
		PUCHAR func = (PUCHAR)MmGetSystemRoutineAddress(&unName);
		pte_base = *(PULONG64)(func + 0x22);
		return pte_base;
	}

	return pte_base;
}

void PageAttrHide::GetLineAddrPteTable(_Inout_ PteTable* Table)
{


	//首先获取PteBase

	ULONG_PTR PteBase = GetPteBase();

	UINT64 LineAddr = Table->pLineAddr & 0x0000ffffffffffff;

	//>>12第几个Pte  <<3代表8个字节

	PteBase &= 0x0000FFFFFFFFFFFF; //先清除前16位

	Table->Pte = ((LineAddr / 4096) * 8) + PteBase;

	Table->Pde = ((Table->Pte / 4096) * 8) + PteBase;

	Table->PdPte = ((Table->Pde / 4096) * 8) + PteBase;

	Table->Pml4e = ((Table->PdPte / 4096) * 8) + PteBase;

	Table->Pte |= 0xFFFF000000000000;

	Table->Pde |= 0xFFFF000000000000;

	Table->PdPte |= 0xFFFF000000000000;

	Table->Pml4e |= 0xFFFF000000000000;



}
#pragma warning(disable : 4100)
#pragma warning(disable : 4189)
void PageAttrHide::ChangeVadAttributes(ULONG_PTR uAddr, UINT32 Attributes)
{

	UINT64 phPteIndex;
	PteTable Table;
	Table.pLineAddr = uAddr;
	ULONG_PTR uOrginPte = 0x10;//原始PTE


	ULONG_PTR MmPfnDataBase = GetMmPfnDataBase();

	//x64 mmpfn 大小 0x30
	//OriginalPte 在0x28偏移处

	GetLineAddrPteTable(&Table);

	//获取物理地址
	phPteIndex = *(UINT64*)(Table.Pte);

	//获取物理地址索引
	phPteIndex &= 0x0000fffffffff000;
	phPteIndex = phPteIndex >> 12;
	//解析原型PTE
	MMPTE_SOFTWARE* pOriginPte = (MMPTE_SOFTWARE*)(MmPfnDataBase + uMmpfnSize * phPteIndex + uOrginPte);
	//修改属性
	pOriginPte->Protection = Attributes;

}

bool PageAttrHide::HidePagesExecuteMemory(HANDLE ProcessId, PVOID HideAddress, size_t size) {

	//首先要获取物理PTE 然后循环修改

	KAPC_STATE apc = { 0 };

	PEPROCESS Process = nullptr;

	if (!NT_SUCCESS(PsLookupProcessByProcessId(ProcessId, &Process))) {

		DbgPrintEx(77, 0, "[OxygenDriver]info:unable to get process\r\n");

		return false;
	}

	KeStackAttachProcess(Process, &apc);

	PUCHAR HideStartAddress = (PUCHAR)((UINT64)HideAddress & 0xFFFFFFFFFFFFF000);

	if (size % 0x1000) size = (size + 0x1000) & 0xFFFFFFFFFFFFF000;

	PUCHAR HideEndAddress = (PUCHAR)(HideStartAddress + size);

	PteTable table = { 0 };

	for (PUCHAR i = HideStartAddress; i > HideEndAddress; i += PAGE_SIZE) {


		table.pLineAddr = (UINT64)HideStartAddress;

		GetLineAddrPteTable(&table);

		//一般只需要修改PTe 和 Pde即可

		PUINT64 Pte = (PUINT64)table.Pte;
		PUINT64 Pde = (PUINT64)table.Pde;

		//修改最高位 置0

		__try {

			*Pte &= 0x7FFFFFFFFFFFFFFF;

			*Pde &= 0x7FFFFFFFFFFFFFFF;
		}
		__except (1) {

			ObDereferenceObject(Process);
			KeUnstackDetachProcess(&apc);

			return false;
		}
	}

	ObDereferenceObject(Process);
	KeUnstackDetachProcess(&apc);


	return true;

}

