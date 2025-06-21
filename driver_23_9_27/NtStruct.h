#pragma once
typedef struct _SYSTEM_THREAD_INFORMATION {
    LARGE_INTEGER KernelTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER CreateTime;
    ULONG WaitTime;
    PVOID StartAddress;
    CLIENT_ID ClientId;
    KPRIORITY Priority;
    LONG BasePriority;
    ULONG ContextSwitchCount;
    ULONG State;
    KWAIT_REASON WaitReason;
}SYSTEM_THREAD_INFORMATION, * PSYSTEM_THREAD_INFORMATION;

typedef struct _SYSTEM_PROCESS_INFORMATION {
    ULONG NextEntryOffset;
    ULONG NumberOfThreads;
    LARGE_INTEGER Reserved[3];
    LARGE_INTEGER CreateTime;
    LARGE_INTEGER UserTime;
    LARGE_INTEGER KernelTime;
    UNICODE_STRING ImageName;
    KPRIORITY BasePriority;
    HANDLE ProcessId;
    HANDLE InheritedFromProcessId;
    ULONG HandleCount;
    ULONG Reserved2[2];
    ULONG PrivatePageCount;
    VM_COUNTERS VirtualMemoryCounters;
    IO_COUNTERS IoCounters;
    SYSTEM_THREAD_INFORMATION Threads[0];
} SYSTEM_PROCESS_INFORMATION, * PSYSTEM_PROCESS_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASS {
    SystemBasicInformation,
    SystemProcessorInformation,
    SystemPerformanceInformation,
    SystemTimeOfDayInformation,
    SystemPathInformation,
    SystemProcessInformation, //5
    SystemCallCountInformation,
    SystemDeviceInformation,
    SystemProcessorPerformanceInformation,
    SystemFlagsInformation,
    SystemCallTimeInformation,
    SystemModuleInformation,
    SystemLocksInformation,
    SystemStackTraceInformation,
    SystemPagedPoolInformation,
    SystemNonPagedPoolInformation,
    SystemHandleInformation,
    SystemObjectInformation,
    SystemPageFileInformation,
    SystemVdmInstemulInformation,
    SystemVdmBopInformation,
    SystemFileCacheInformation,
    SystemPoolTagInformation,
    SystemInterruptInformation,
    SystemDpcBehaviorInformation,
    SystemFullMemoryInformation,
    SystemLoadGdiDriverInformation,
    SystemUnloadGdiDriverInformation,
    SystemTimeAdjustmentInformation,
    SystemSummaryMemoryInformation,
    SystemNextEventIdInformation,
    SystemEventIdsInformation,
    SystemCrashDumpInformation,
    SystemExceptionInformation,
    SystemCrashDumpStateInformation,
    SystemKernelDebuggerInformation,
    SystemContextSwitchInformation,
    SystemRegistryQuotaInformation,
    SystemExtendServiceTableInformation,
    SystemPrioritySeperation,
    SystemPlugPlayBusInformation,
    SystemDockInformation,
    SystemPowerInformation2,
    SystemProcessorSpeedInformation,
    SystemCurrentTimeZoneInformation,
    SystemLookasideInformation
} SYSTEM_INFORMATION_CLASS, * PSYSTEM_INFORMATION_CLASS;

typedef struct _SYSTEM_MODULE_ENTRY {
    HANDLE Section;
    PVOID MappedBase;
    PVOID ImageBase;
    ULONG ImageSize;
    ULONG Flags;
    USHORT LoadOrderIndex;
    USHORT InitOrderIndex;
    USHORT LoadCount;
    USHORT OffsetToFileName;
    UCHAR FullPathName[256];
} SYSTEM_MODULE_ENTRY, * PSYSTEM_MODULE_ENTRY;

typedef struct _SYSTEM_MODULE_INFORMATION {
    ULONG Count;
    SYSTEM_MODULE_ENTRY Module[1];
} SYSTEM_MODULE_INFORMATION, * PSYSTEM_MODULE_INFORMATION;

#define PFN_TO_PAGE(pfn) (pfn << PAGE_SHIFT)

#define PAGE_TO_PFN(pfn) (pfn >> PAGE_SHIFT)

#pragma pack(push, 1)
typedef union CR3_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Ignored1 : 3;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Ignored2 : 7;
		ULONG64 Pml4 : 40;
		ULONG64 Reserved : 12;
	};
} PTE_CR3;

typedef union VIRT_ADDR_
{
	ULONG64 Value;
	void* Pointer;
	struct
	{
		ULONG64 Offset : 12;
		ULONG64 PtIndex : 9;
		ULONG64 PdIndex : 9;
		ULONG64 PdptIndex : 9;
		ULONG64 Pml4Index : 9;
		ULONG64 Reserved : 16;
	};
} VIRTUAL_ADDRESS;

typedef union PML4E_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Ignored1 : 1;
		ULONG64 Reserved1 : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pdpt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PML4E;

typedef union PDPTE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pd : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDPTE;

typedef union PDE_
{
	ULONG64 Value;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 PageSize : 1;
		ULONG64 Ignored2 : 4;
		ULONG64 Pt : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PDE;

typedef union PTE_
{
	ULONG64 Value;
	VIRTUAL_ADDRESS VirtualAddress;
	struct
	{
		ULONG64 Present : 1;
		ULONG64 Rw : 1;
		ULONG64 User : 1;
		ULONG64 WriteThrough : 1;
		ULONG64 CacheDisable : 1;
		ULONG64 Accessed : 1;
		ULONG64 Dirty : 1;
		ULONG64 Pat : 1;
		ULONG64 Global : 1;
		ULONG64 Ignored1 : 3;
		ULONG64 PageFrame : 40;
		ULONG64 Ignored3 : 11;
		ULONG64 Xd : 1;
	};
} PTE;
#pragma pack(pop)