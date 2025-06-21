#include "pch.h"
#include "util.h"


size_t util::Offset__EPROCESS_Token{};
size_t util::Offset__TEB_TlsSlots{};
size_t util::Offset__KTHREAD_Process{};
size_t util::Offset__KTHREAD_Win32Thread{};
size_t util::Offset__ETHREAD_Cid{};
size_t util::Offset__EPROCESS_ImageFileName{};
size_t util::Offset__KPROCESS_DirectoryTableBase{};
size_t util::Offset__KPROCESS_UserDirectoryTableBase{};
size_t util::Offset__KTHREAD__KAPC_STATE{};

NTSTATUS(*pZwQuerySystemInformation)(ULONG, PVOID, ULONG, PULONG) = nullptr;
NTSTATUS(*pPsSuspendThread)(PETHREAD,PULONG) = nullptr;
NTSTATUS(*pPsResumeThread)(PETHREAD, PULONG) = nullptr;
NTSTATUS(*pZwGetNextThread)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE) = nullptr;
PVOID(*pPsGetThreadTeb)(PETHREAD) = nullptr;
NTSTATUS(*pPsGetContextThread)(PETHREAD, PCONTEXT, KPROCESSOR_MODE) = nullptr;
NTSTATUS(*pZwGetContextThread)(HANDLE, PCONTEXT) = nullptr;
NTSTATUS(*pZwOpenThread)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID) = nullptr;
NTSTATUS(*pPsSetContextThread)(PETHREAD, PCONTEXT, KPROCESSOR_MODE) = nullptr;
PVOID(*pRtlFindExportedRoutineByName)(PVOID, PCCH) = nullptr;
NTSTATUS(*pRtlCreateUserThread)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, LPVOID, LPVOID, HANDLE, PCLIENT_ID) = nullptr;
ULONG64(*pPsGetCurrentProcessByThread)(ULONG64 a1) = nullptr;

bool util::init()
{
	oxygenPdb::Pdber ntos(L"ntoskrnl.exe");

    if (!ntos.init())
        return false;

 

   // oxygenPdb::Pdber win32kfull(L"win32kfull.sys");
    //if (!win32kfull.init())
       //return false;
 
	//通信用
	//auto HalPrivateDispatchTable = ntos.GetOffset("ntoskrnl", "HalPrivateDispatchTable");
	//DbgPrintEx(0, 0, "[+] HalPrivateDispatchTable %llX\n", HalPrivateDispatchTable);
	//if (!HalPrivateDispatchTable)
	//	return false;

	Offset__EPROCESS_Token = ntos.GetOffset("_EPROCESS", "Token");
	if (!Offset__EPROCESS_Token)
		return false;

    Offset__TEB_TlsSlots = ntos.GetOffset("_TEB", "TlsSlots");
    if (!Offset__TEB_TlsSlots)
        return false;

    Offset__KTHREAD_Process = ntos.GetOffset("_KTHREAD", "Process");
    if (!Offset__KTHREAD_Process)
        return false;

    Offset__KTHREAD_Win32Thread = ntos.GetOffset("_KTHREAD", "Win32Thread");
    if (!Offset__KTHREAD_Win32Thread)
        return false;

    Offset__ETHREAD_Cid = ntos.GetOffset("_ETHREAD", "Cid");
    if (!Offset__ETHREAD_Cid)
        return false;


    Offset__KPROCESS_DirectoryTableBase = ntos.GetOffset("_KPROCESS", "DirectoryTableBase");
    if (!Offset__KPROCESS_DirectoryTableBase)
        return false;

    Offset__KPROCESS_UserDirectoryTableBase = ntos.GetOffset("_KPROCESS", "UserDirectoryTableBase");
    if (!Offset__KPROCESS_UserDirectoryTableBase)
        return false;


    Offset__EPROCESS_ImageFileName = ntos.GetOffset("_EPROCESS", "ImageFileName");
    if (!Offset__EPROCESS_ImageFileName)
        return false;


    Offset__KTHREAD__KAPC_STATE = ntos.GetOffset("_KTHREAD", "ApcState");
    if (!Offset__KTHREAD__KAPC_STATE)
        return false;



    pZwQuerySystemInformation = reinterpret_cast<NTSTATUS(*)(ULONG, PVOID, ULONG, PULONG)>(ntos.GetPointer("ZwQuerySystemInformation"));
    if (!pZwQuerySystemInformation)
        return false;

    pPsSuspendThread = reinterpret_cast<NTSTATUS(*)(PETHREAD, PULONG)>(ntos.GetPointer("PsSuspendThread"));
    if (!pPsSuspendThread)
        return false;

    pPsResumeThread = reinterpret_cast<NTSTATUS(*)(PETHREAD, PULONG)>(ntos.GetPointer("PsResumeThread"));
    if (!pPsResumeThread)
        return false;

    pZwGetNextThread = reinterpret_cast<NTSTATUS(*)(HANDLE, HANDLE, ACCESS_MASK, ULONG, ULONG, PHANDLE)>(ntos.GetPointer("ZwGetNextThread"));
    if (!pZwGetNextThread)
        return false;

    pPsGetThreadTeb = reinterpret_cast<PVOID(*)(PETHREAD)>(ntos.GetPointer("PsGetThreadTeb"));
    if (!pPsGetThreadTeb)
        return false;
    
    pPsGetContextThread = reinterpret_cast<NTSTATUS(*)(PETHREAD, PCONTEXT, KPROCESSOR_MODE)>(ntos.GetPointer("PsGetContextThread"));
    if (!pPsGetContextThread)
        return false;

    pZwGetContextThread = reinterpret_cast<NTSTATUS(*)(HANDLE, PCONTEXT)>(ntos.GetPointer("ZwGetContextThread"));
    if (!pZwGetContextThread)
        return false;

    pZwOpenThread = reinterpret_cast<NTSTATUS(*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID)>(ntos.GetPointer("ZwOpenThread"));
    if (!pZwOpenThread)
        return false;

    pPsSetContextThread = reinterpret_cast<NTSTATUS(*)(PETHREAD, PCONTEXT, KPROCESSOR_MODE)>(ntos.GetPointer("PsSetContextThread"));
    if (!pPsSetContextThread)
        return false;

    pRtlFindExportedRoutineByName = reinterpret_cast<PVOID(*)(PVOID, PCCH)>(ntos.GetPointer("RtlFindExportedRoutineByName"));
    if (!pRtlFindExportedRoutineByName)
        return false;

    pRtlCreateUserThread = reinterpret_cast<NTSTATUS(*)(HANDLE, PSECURITY_DESCRIPTOR, BOOL, ULONG, PULONG, PULONG, LPVOID, LPVOID, HANDLE, PCLIENT_ID)>(ntos.GetPointer("RtlCreateUserThread"));
    if (!pRtlCreateUserThread)
        return false;


    pPsGetCurrentProcessByThread = reinterpret_cast<ULONG64(*)(ULONG64)>(ntos.GetPointer("PsGetCurrentProcessByThread"));
    if (!pPsGetCurrentProcessByThread)
        return false;

	return true;
}



NTSTATUS util::GetProcessIdByName(wchar_t* ProcessName, HANDLE* pProcessId)
{
    ULONG cbBuffer = 0x8000; //32k
    PVOID pSystemInfo;
    NTSTATUS status;
    PSYSTEM_PROCESS_INFORMATION pInfo;

    //为查找进程分配足够的空间
    do
    {
        pSystemInfo = ExAllocatePool(NonPagedPool, cbBuffer);
        if (pSystemInfo == NULL) //申请空间失败，返回
            return 1;

        status = pZwQuerySystemInformation(SystemProcessInformation, pSystemInfo, cbBuffer, NULL);
        if (status == STATUS_INFO_LENGTH_MISMATCH) //空间不足
        {
            ExFreePool(pSystemInfo);
            cbBuffer *= 2;
        }
        else if (!NT_SUCCESS(status))
        {
            ExFreePool(pSystemInfo);
            return 1;
        }

    } while (status == STATUS_INFO_LENGTH_MISMATCH); //如果是空间不足，就一直循环
    
    pInfo = (PSYSTEM_PROCESS_INFORMATION)pSystemInfo; //把得到的信息放到pInfo中

    for (;;)
    {
        LPWSTR pszProcessName = pInfo->ImageName.Buffer;
        if (pszProcessName == NULL)
            pszProcessName = L"NULL";

        if (wcscmp(pszProcessName, ProcessName) == 0)
        {
            //DbgPrintEx(0, 0, "PID:%d, process name:%S \n", pInfo->ProcessId, pszProcessName);
            *pProcessId = pInfo->ProcessId;
            return STATUS_SUCCESS;
        }

        if (pInfo->NextEntryOffset == 0) //==0，说明到达进程链的尾部了
            break;

        pInfo = (PSYSTEM_PROCESS_INFORMATION)(((PUCHAR)pInfo) + pInfo->NextEntryOffset); //遍历
        

    }
    return 1;
}

PVOID util::QuerySystemInformation(SYSTEM_INFORMATION_CLASS SystemInfoClass, ULONG* size)
{
    int currAttempt = 0;
    int maxAttempt = 20;


QueryTry:
    if (currAttempt >= maxAttempt)
        return 0;

    currAttempt++;
    ULONG neededSize = 0;
    pZwQuerySystemInformation(SystemInfoClass, NULL, neededSize, &neededSize);
    if (!neededSize)
        goto QueryTry;

    ULONG allocationSize = neededSize;
    PVOID informationBuffer = ExAllocatePool(NonPagedPool, allocationSize);
    if (!informationBuffer)
        goto QueryTry;

    NTSTATUS status = pZwQuerySystemInformation(SystemInfoClass, informationBuffer, neededSize, &neededSize);
    if (!NT_SUCCESS(status))
    {
        ExFreePoolWithTag(informationBuffer, 0);
        goto QueryTry;
    }

    *size = allocationSize;
    return informationBuffer;
}

UINT64 util::GetKernelModuleBase(const char* name)
{
    ULONG size = 0;
    PSYSTEM_MODULE_INFORMATION moduleInformation = (PSYSTEM_MODULE_INFORMATION)QuerySystemInformation(SystemModuleInformation, &size);

    if (!moduleInformation || !size)
        return 0;

    for (size_t i = 0; i < moduleInformation->Count; i++)
    {
        char* fileName = (char*)moduleInformation->Module[i].FullPathName + moduleInformation->Module[i].OffsetToFileName;
        if (!strcmp(fileName, name))
        {
            UINT64 imageBase = (UINT64)moduleInformation->Module[i].ImageBase;
            ExFreePoolWithTag(moduleInformation, 0);
            return imageBase;
        }
    }

    ExFreePoolWithTag(moduleInformation, 0);
}

NTSTATUS util::MyCreateThread(PVOID entry)
{
    HANDLE threadHandle = NULL;
    NTSTATUS status = PsCreateSystemThread(&threadHandle, NULL, NULL, NULL, NULL, (PKSTART_ROUTINE)entry, NULL);
    if (!NT_SUCCESS(status))
        return status;
    ZwClose(threadHandle);
    return status;
}

void util::Sleep(int ms)
{
    LARGE_INTEGER time = { 0 };
    time.QuadPart = -(ms) * 10 * 1000;
    KeDelayExecutionThread(KernelMode, TRUE, &time);
}

PVOID util::PhysicalToVirtual(ULONG64 address)
{
    PHYSICAL_ADDRESS physical;
    physical.QuadPart = address;
    return MmGetVirtualForPhysical(physical);
}

//NTSTATUS util::MyPsLookupProcessByProcessId(DWORD ProcessId, PEPROCESS* pEprocess,ULONG64* res)
//{
//    DbgBreak();
//    HANDLE hProcess{};
//    OBJECT_ATTRIBUTES Object{};
//    InitializeObjectAttributes(&Object, NULL, OBJ_KERNEL_HANDLE, NULL, NULL);
//    CLIENT_ID Cid{};
//    Cid.UniqueProcess = HANDLE(ProcessId);
//    auto status = ZwOpenProcess(&hProcess, PROCESS_ALL_ACCESS, &Object, &Cid);
//    if (!NT_SUCCESS(status))
//        return status;
//
//    HANDLE hThread{};
//    status = pZwGetNextThread(hProcess, NULL, THREAD_ALL_ACCESS, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, 0, &hThread);
//    if (status != STATUS_SUCCESS)
//    {
//        ZwClose(hProcess);
//        return status;
//    }
//    //PsGetCurrentThread()
//    
//    
//    
//    PETHREAD pEthread{};
//    status = ObReferenceObjectByHandle(hThread, THREAD_ALL_ACCESS, *PsThreadType, KernelMode, (PVOID*)&pEthread, NULL);
//    if (status != STATUS_SUCCESS)
//    {
//        ZwClose(hProcess);
//        ZwClose(hThread);
//        return status;
//    }
//    ZwClose(hProcess);
//    ZwClose(hThread);
//    
//    auto result = pPsGetCurrentProcessByThread(ULONG64(pEthread));
//
//    if (pEprocess != nullptr)
//        *pEprocess = (PEPROCESS)result;
//
//    if (res != nullptr)
//        *res = result;
//
//    return STATUS_SUCCESS;
//
//}
//
//
