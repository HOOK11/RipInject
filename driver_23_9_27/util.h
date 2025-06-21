#pragma once


extern NTSTATUS(*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG);
extern NTSTATUS(*pPsSuspendThread)(PETHREAD, PULONG);
extern NTSTATUS(*pPsResumeThread)(PETHREAD, PULONG);
extern NTSTATUS(*pZwGetNextThread)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE);
extern PVOID(*pPsGetThreadTeb)(PETHREAD);
extern NTSTATUS(*pPsGetContextThread)(PETHREAD, PCONTEXT, KPROCESSOR_MODE);
extern NTSTATUS(*pZwGetContextThread)(HANDLE, PCONTEXT);
extern NTSTATUS(*pZwOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);
extern NTSTATUS(*pPsSetContextThread)(PETHREAD, PCONTEXT, KPROCESSOR_MODE);
extern PVOID(*pRtlFindExportedRoutineByName)(PVOID, PCCH);
extern NTSTATUS(*pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, LPVOID, LPVOID, HANDLE, PCLIENT_ID);
extern ULONG64(*pPsGetCurrentProcessByThread)(ULONG64 a1);
namespace util
{
	extern size_t Offset__EPROCESS_Token;
	extern size_t Offset__TEB_TlsSlots;
	extern size_t Offset__KTHREAD_Process;
	extern size_t Offset__KTHREAD_Win32Thread;
	extern size_t Offset__ETHREAD_Cid;
	extern size_t Offset__EPROCESS_ImageFileName;
	extern size_t Offset__KPROCESS_DirectoryTableBase;
	extern size_t Offset__KPROCESS_UserDirectoryTableBase;
	extern size_t Offset__KTHREAD__KAPC_STATE;

	bool init();


	NTSTATUS GetProcessIdByName(wchar_t* ProcessName, HANDLE* pProcessId);

	PVOID QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, ULONG* size);

	UINT64 GetKernelModuleBase(const char* name);

	NTSTATUS MyCreateThread(PVOID entry);

	void Sleep(int ms);

	PVOID PhysicalToVirtual(ULONG64 address);
}

