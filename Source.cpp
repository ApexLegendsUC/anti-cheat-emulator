#include <ntifs.h>
#include <ntddk.h>
extern "C" {
#include "NativeStructs.h"
}
#include "defs.h"

#define xorstr_(x) x

#define POOL_TAG 'enoN'

void sleep(LONG milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(10000ll * milliseconds);

	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


PVOID g_KernelBase = nullptr;

EXTERN_C NTSYSAPI
PIMAGE_NT_HEADERS
NTAPI
RtlImageNtHeader(PVOID Base);

void get_ntoskrnl_text_section(uintptr_t* start_addr, ULONG* len)
{
	*start_addr = NULL;
	*len = NULL;
	auto base = GetKernelBase();
	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return; 

	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		//DbgPrint("section: %s\r\n", pSection->Name);
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, ".text");
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			*start_addr = (uintptr_t)((PUCHAR)base + pSection->VirtualAddress);
			*len = pSection->Misc.VirtualSize;
			return;
		}
	}
}

NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_INVALID_PARAMETER;
	int cIndex = 0;
	for (ULONG_PTR i = 0; i < size - len; i++)
	{
		BOOLEAN found = TRUE;
		for (ULONG_PTR j = 0; j < len; j++)
		{
			if (pattern[j] != wildcard && pattern[j] != ((PCUCHAR)base)[i + j])
			{
				found = FALSE;
				break;
			}
		}

		if (found != FALSE && cIndex++ == index)
		{
			*ppFound = (PUCHAR)base + i;
			return STATUS_SUCCESS;
		}
	}

	return STATUS_NOT_FOUND;
}

NTSTATUS BBScanSection(IN PCCHAR section, IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, OUT PVOID* ppFound, PVOID base = nullptr)
{
	//ASSERT(ppFound != NULL);
	if (ppFound == NULL)
		return STATUS_INVALID_PARAMETER;

	if (nullptr == base)
		base = GetKernelBase();
	if (base == nullptr)
		return STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_INVALID_IMAGE_FORMAT;

	//PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)(pHdr + 1);
	PIMAGE_SECTION_HEADER pFirstSection = (PIMAGE_SECTION_HEADER)((uintptr_t)&pHdr->FileHeader + pHdr->FileHeader.SizeOfOptionalHeader + sizeof(IMAGE_FILE_HEADER));

	for (PIMAGE_SECTION_HEADER pSection = pFirstSection; pSection < pFirstSection + pHdr->FileHeader.NumberOfSections; pSection++)
	{
		//DbgPrint("section: %s\r\n", pSection->Name);
		ANSI_STRING s1, s2;
		RtlInitAnsiString(&s1, section);
		RtlInitAnsiString(&s2, (PCCHAR)pSection->Name);
		if (RtlCompareString(&s1, &s2, TRUE) == 0)
		{
			PVOID ptr = NULL;
			NTSTATUS status = BBSearchPattern(pattern, wildcard, len, (PUCHAR)base + pSection->VirtualAddress, pSection->Misc.VirtualSize, &ptr);
			if (NT_SUCCESS(status)) {
				*(PULONG64)ppFound = (ULONG_PTR)(ptr); //- (PUCHAR)base
				//DbgPrint("found\r\n");
				return status;
			}
			//we continue scanning because there can be multiple sections with the same name.
		}
	}

	return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;
}

PSYSTEM_MODULE_INFORMATION GetKernelModuleList()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	ZwQuerySystemInformation(
		SystemModuleInformation,
		&neededSize,
		0,
		&neededSize
	);

	PSYSTEM_MODULE_INFORMATION pModuleList;

	pModuleList = (PSYSTEM_MODULE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG);
	if (pModuleList == NULL)
	{
		return FALSE;
	}

	status = ZwQuerySystemInformation(SystemModuleInformation,
		pModuleList,
		neededSize,
		0
	);

	/*for (ULONG i = 0; i < pModuleList->ulModuleCount; i++)
	{
		auto name_offset = pModuleList->Modules[i].ModuleNameOffset;
		if (name_offset > 256)
			break;
		if (_stricmp(&pModuleList->Modules[i].ImageName[name_offset], name) == NULL) {
			auto address = (UINT64)pModuleList->Modules[i].Base;
			ExFreePoolWithTag(pModuleList, POOL_TAG);
			return address;
		}
	}
	*/

	//ExFreePoolWithTag(pModuleList, POOL_TAG);

	return pModuleList;
}



void get_thread_start_address(PETHREAD ThreadObj, uintptr_t* pStartAddr)
{
	*pStartAddr = NULL;
	HANDLE hThread;
	if (!NT_SUCCESS(ObOpenObjectByPointer(ThreadObj, OBJ_KERNEL_HANDLE, nullptr, GENERIC_READ, *PsThreadType, KernelMode, &hThread))) {
		DbgPrint("ObOpenObjectByPointer failed.\n");
		return;
	}

	uintptr_t start_addr;
	ULONG returned_bytes;

	if (!NT_SUCCESS(NtQueryInformationThread(hThread, ThreadQuerySetWin32StartAddress, &start_addr, sizeof(start_addr), &returned_bytes))) {
		DbgPrint("NtQueryInformationThread failed.\n");
		NtClose(hThread);
		return;
	}

	if (MmIsAddressValid((void*)start_addr)) {
		*pStartAddr = start_addr;
	}
	else
		DbgPrint("(not a detection) Invalid start addr %p.\r\n", start_addr);

	NtClose(hThread);
}

bool is_address_outside_of_module_list(PSYSTEM_MODULE_INFORMATION pModuleList, uintptr_t addr)
{
	if (addr == NULL)
		return false;
	__try {
		for (ULONG i = 0; i < pModuleList->ulModuleCount; i++)
		{
			if (addr >= reinterpret_cast<uintptr_t>(pModuleList->Modules[i].Base) && 
				addr < reinterpret_cast<uintptr_t>(pModuleList->Modules[i].Base) + pModuleList->Modules[i].Size) {
				return false;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Access Violation was raised (is_address_outside_of_module_list).\n");
	}
	return true;
}

void print_module_name(PSYSTEM_MODULE_INFORMATION pModuleList, uintptr_t addr)
{
	if (addr == NULL)
		return;
	__try {
		for (ULONG i = 0; i < pModuleList->ulModuleCount; i++)
		{
			if (addr >= reinterpret_cast<uintptr_t>(pModuleList->Modules[i].Base) && addr < reinterpret_cast<uintptr_t>(pModuleList->Modules[i].Base) + pModuleList->Modules[i].Size) {
				auto name_offset = pModuleList->Modules[i].ModuleNameOffset;
				if (name_offset > 256)
					continue;
				DbgPrint("module: %s\n", &pModuleList->Modules[i].ImageName[name_offset]);
				return;
			}
		}
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Access Violation was raised (is_address_outside_of_module_list).\n");
	}
	DbgPrint("Module: <unknown>\n");
}

//PsGetCurrentThreadStackBase
ULONG GetThreadStackBaseOffset()
{
	UNICODE_STRING s = RTL_CONSTANT_STRING(L"PsGetCurrentThreadStackBase");

	auto CurrentThreadStackBase = (uintptr_t(NTAPI*)())MmGetSystemRoutineAddress(&s);
	auto CurrentThread = (uintptr_t)PsGetCurrentThread();
	auto current_stack = CurrentThreadStackBase();

	ULONG Offset = NULL;
	while (*PULONGLONG(CurrentThread + Offset) != current_stack)
		Offset += 8;

	return Offset;
}

ULONG GetThreadStackLimitOffset()
{
	UNICODE_STRING s = RTL_CONSTANT_STRING(L"PsGetCurrentThreadStackLimit");

	auto CurrentThreadStackLimit = (uintptr_t(NTAPI*)())MmGetSystemRoutineAddress(&s);
	auto CurrentThread = (uintptr_t)PsGetCurrentThread();
	auto current_stack = CurrentThreadStackLimit();

	ULONG Offset = NULL;
	while (*PULONGLONG(CurrentThread + Offset) != current_stack)
		Offset += 8;

	return Offset;
}

ULONG GetInitialThreadStackOffset()
{
	UNICODE_STRING s = RTL_CONSTANT_STRING(L"IoGetInitialStack");

	auto CurrentThreadStack = (uintptr_t(NTAPI*)())MmGetSystemRoutineAddress(&s);
	auto CurrentThread = (uintptr_t)PsGetCurrentThread();
	auto current_stack = CurrentThreadStack();

	ULONG Offset = NULL;
	while (*PULONGLONG(CurrentThread + Offset) != current_stack)
		Offset += 8;

	return Offset;
}

ULONG GetThreadCurrentStackLocationOffset(PETHREAD ThreadObj, ULONG stack_base_offset, ULONG stack_limit_offset, ULONG initial_stack_offset)
{
	auto thread_stack_base = stack_base_offset ? *(uintptr_t*)((uintptr_t)ThreadObj + stack_base_offset) : 0;
	auto thread_stack_limit = stack_limit_offset ? *(uintptr_t*)((uintptr_t)ThreadObj + stack_limit_offset) : 0;

	if (!thread_stack_base || !thread_stack_limit || !initial_stack_offset)
		return NULL;

	auto thread_obj = (uintptr_t)ThreadObj;

	ULONG Offset = NULL;
	while (Offset < 0x2F8) {
		if (Offset != initial_stack_offset && *PULONGLONG(thread_obj + Offset) < thread_stack_base && *PULONGLONG(thread_obj + Offset) > thread_stack_limit)
			return Offset;
		Offset += 8;
	}

	return NULL;
}

#define KELOCKTHREAD 0x12EE7C
#define KERESUMETHREAD 0x30E90

typedef uintptr_t(NTAPI*tThreadLock)(void* thread_obj);


bool printed_stack_offsets = false;
ULONG CopyStack(PETHREAD ThreadObj, void* copied_stack, ULONG copied_stack_buffer_len)
{
	RtlZeroMemory(copied_stack, copied_stack_buffer_len);
	auto stack_base_offset = GetThreadStackBaseOffset();
	auto stack_limit_offset = GetThreadStackLimitOffset();
	auto initial_stack_offset = GetInitialThreadStackOffset();
	if (!printed_stack_offsets) {
		DbgPrint("stack_base_offset = 0x%x, stack_limit_offset = 0x%x, initial_stack_offset = 0x%x\n", stack_base_offset, stack_limit_offset, initial_stack_offset);
		printed_stack_offsets = true;
	}

	auto stack_base = stack_base_offset ? *(uintptr_t*)((uintptr_t)ThreadObj + stack_base_offset) : 0;
	auto stack_limit = stack_limit_offset ? *(uintptr_t*)((uintptr_t)ThreadObj + stack_limit_offset) : 0;
	auto initial_stack = initial_stack_offset ? *(uintptr_t*)((uintptr_t)ThreadObj + initial_stack_offset) : 0;
	auto current_stack_location_offset = GetThreadCurrentStackLocationOffset(ThreadObj, stack_base_offset, stack_limit_offset, initial_stack_offset);
	auto pcurrent_stack_location = current_stack_location_offset ? (uintptr_t*)((uintptr_t)ThreadObj + current_stack_location_offset) : nullptr;
	if (ThreadObj == KeGetCurrentThread() || !stack_base || !stack_limit || !initial_stack || !current_stack_location_offset || PsIsThreadTerminating(ThreadObj) || pcurrent_stack_location == nullptr)
		return NULL;

	tThreadLock lock_thread = (tThreadLock)((uintptr_t)GetKernelBase() + KELOCKTHREAD);
	tThreadLock resume_thread = (tThreadLock)((uintptr_t)GetKernelBase() + KERESUMETHREAD);


	//to-do: lock thread to make it more stable

#define KTHREAD_SPINLOCK_OFFSET 0x2E0 //taken from KeSuspendThread
	
	//KeAcquireSpinLockAtDpcLevel((PKSPIN_LOCK)((uintptr_t)ThreadObj + KTHREAD_SPINLOCK_OFFSET)); //no idea what i'm doing
	lock_thread(ThreadObj);

	auto current_stack_location = *pcurrent_stack_location;
	auto current_stack_size = stack_base - current_stack_location;
	if (current_stack_location > stack_limit && current_stack_location < stack_base && MmGetPhysicalAddress((PVOID)current_stack_location).QuadPart) {
		if (current_stack_size > copied_stack_buffer_len)
			current_stack_size = copied_stack_buffer_len;
		if (!MmIsAddressValid((PVOID)current_stack_location)) {
			//KeReleaseSpinLockFromDpcLevel((PKSPIN_LOCK)((uintptr_t)ThreadObj + KTHREAD_SPINLOCK_OFFSET));
			resume_thread(ThreadObj);
			return NULL;
		}
		memmove(copied_stack, (PVOID)current_stack_location, current_stack_size);
		//KeReleaseSpinLockFromDpcLevel((PKSPIN_LOCK)((uintptr_t)ThreadObj + KTHREAD_SPINLOCK_OFFSET));
	}
	else
		current_stack_size = NULL;
	resume_thread(ThreadObj);

	return current_stack_size;
}

struct sStackWalkList {
	uintptr_t Rsp, Rip;
};

#include <intrin.h>

typedef LOGICAL(NTAPI*tMmCanThreadFault)(VOID);

int c = 0;
void walk_stack_thread(PETHREAD ThreadObj, sStackWalkList* results)
{
	/*tMmCanThreadFault MmCanThreadFault = (tMmCanThreadFault)((uintptr_t)GetKernelBase() + MM_CAN_THREAD_FAULT_OFFSET);

	if (MmCanThreadFault()) {
		DbgPrint("Thread can fault\r\n");
		return;
	}*/

	UCHAR copied_stack[0x1000];
	if (auto stack_len = CopyStack(ThreadObj, copied_stack, sizeof(copied_stack))) {
		//if (stack_len != NULL)
			//DbgPrint("copied stack, size = %d\n", stack_len);
		
		if (stack_len >= 0x48 && stack_len != 0x1000 && (c == 0)) {
			int FuncEnumCnt = 0;
			
			CONTEXT ctx;
			RtlZeroMemory(&ctx, sizeof(ctx));
			ctx.Rip = *PULONGLONG(&copied_stack[0] + 0x38);
			ctx.Rsp = reinterpret_cast<uintptr_t>(&copied_stack[0] + 0x40);

			//KNONVOLATILE_CONTEXT_POINTERS NvContext;
			
			uintptr_t ntoskrnl_text_section_start_addr;
			ULONG len;
			get_ntoskrnl_text_section(&ntoskrnl_text_section_start_addr, &len);
			if (!ntoskrnl_text_section_start_addr || !len)
				return;
			if (ctx.Rip >= ntoskrnl_text_section_start_addr && ctx.Rip < ntoskrnl_text_section_start_addr + len) {
				__try {
					do {
						if (ctx.Rip < reinterpret_cast<uintptr_t>(MmSystemRangeStart) || ctx.Rsp < reinterpret_cast<uintptr_t>(MmSystemRangeStart))
							break;

						if (!MmIsAddressValid((PVOID)ctx.Rip) || !MmIsAddressValid((PVOID)ctx.Rsp)) {
							break;
						}

						results[FuncEnumCnt].Rip = ctx.Rip;
						results[FuncEnumCnt].Rsp = ctx.Rsp;

						DWORD64 ImageBase = NULL;
						auto old_irql = KeRaiseIrqlToDpcLevel();
						auto f = RtlLookupFunctionEntry(ctx.Rip, &ImageBase, NULL);
						KeLowerIrql(old_irql);
						if (!f)
							break;

						PVOID HandlerData = NULL;
						DWORD64 EstablisherFrame = NULL;
#define UNW_FLAG_NHANDLER NULL
						RtlVirtualUnwind(UNW_FLAG_NHANDLER, ImageBase, ctx.Rip, f, &ctx, &HandlerData, &EstablisherFrame, nullptr);
						++FuncEnumCnt;
						if (!ctx.Rip)
							break;
					} while (FuncEnumCnt < 0x20);
					//DbgPrint("enumerated %d functions.\n", FuncEnumCnt);
				}
				__except (EXCEPTION_EXECUTE_HANDLER) {
					DbgPrint("Access Violation was raised (1).\n");
				}

			}

		}
	}
}


//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool_entry.htm
typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		uintptr_t VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, *PSYSTEM_BIGPOOL_ENTRY;

//from http://www.geoffchappell.com/studies/windows/km/ntoskrnl/api/ex/sysinfo/bigpool.htm
typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, *PSYSTEM_BIGPOOL_INFORMATION;

void scan_bigpool_check_1(uintptr_t addr)
{
	ULONG len = 4 * 1024 * 1024;
	auto mem = ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, len, POOL_TAG);

	if (NT_SUCCESS(ZwQuerySystemInformation(SystemBigPoolInformation, mem, len, &len))) {
		auto pBuf = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(mem);
		for (ULONG i = 0; i < pBuf->Count; i++) {
			if (pBuf->AllocatedInfo[i].TagUlong == 'enoN' && addr >= pBuf->AllocatedInfo[i].VirtualAddress && addr < pBuf->AllocatedInfo[i].VirtualAddress + pBuf->AllocatedInfo[i].SizeInBytes) {
				if (pBuf->AllocatedInfo[i].SizeInBytes > 0x1000) {
					__try {
						UCHAR zeroedoutpehdr[0x1000]{};
						if (auto pe_hdr = MmMapIoSpace(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, MEMORY_CACHING_TYPE::MmNonCached)) {
							if (memcmp(pe_hdr, zeroedoutpehdr, 0x1000))
								DbgPrint("[DETECTION] running kdmapper/drvmap manual mapped driver detected (99%% confidence).\n");

							MmUnmapIoSpace(pe_hdr, PAGE_SIZE);
						}
						else
							DbgPrint("[DETECTION] Unable to map physical memory to dump/verify but manual map driver detected anyways with 95%% confidence.\n");
					}
					__except (EXCEPTION_EXECUTE_HANDLER) {
						DbgPrint("Access Violation was raised.\n");
					}
				}
			}
		}
	}
	else
		DbgPrint("Failed to get bigpool.\n");

	ExFreePoolWithTag(mem, POOL_TAG);
}


void scan_bigpool_check_2()
{
	ULONG len = 4 * 1024 * 1024;
	auto mem = ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, len, POOL_TAG);

	if (NT_SUCCESS(ZwQuerySystemInformation(SystemBigPoolInformation, mem, len, &len))) {
		auto pBuf = reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(mem);
		for (ULONG i = 0; i < pBuf->Count; i++) {
			__try {
				if (auto page = MmMapIoSpace(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, MEMORY_CACHING_TYPE::MmCached)) {
					if (*(PULONG)((uintptr_t)page + 0x184) == 0xB024BC8B48)
						DbgPrint("[DETECTION] 0xB024BC8B48 found at pool + 0x184\n");
					MmUnmapIoSpace(page, PAGE_SIZE);
				}
				//https://www.unknowncheats.me/forum/2427433-post12.html
				if (pBuf->AllocatedInfo[i].TagUlong == 'SldT')
					DbgPrint("[DETECTION] TdlS pooltag detected\n");


			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("Access Violation was raised (scan_bigpool_check_2).\n");
			}
		}
	}
	else
		DbgPrint("Failed to get bigpool.\n");

	ExFreePoolWithTag(mem, POOL_TAG);
}

void scan_system_threads(PSYSTEM_MODULE_INFORMATION pModuleList)
{
	sleep(1000);
	for (ULONG thrd_id = 4; thrd_id < 0x30000; thrd_id += 4) {
		PETHREAD ThreadObj;
		if (!NT_SUCCESS(PsLookupThreadByThreadId(reinterpret_cast<HANDLE>(thrd_id), &ThreadObj)))
			continue;
		if (!PsIsSystemThread(ThreadObj) || ThreadObj == KeGetCurrentThread()) {
			//DbgPrint("Ignoring non-system thread.\n");
			continue;
		}
		uintptr_t start_addr;
		get_thread_start_address(ThreadObj, &start_addr);
		//DbgPrint("thread start addr = %p\n", start_addr);
		if (is_address_outside_of_module_list(pModuleList, start_addr))
			DbgPrint("[DETECTION] Thread Start Address outside of module list. thread id = %d\n", thrd_id);
		
		if (start_addr && (memcmp((void*)start_addr, "\xFF\xE1", 2) == 0)) {
			DbgPrint("[DETECTION] jmp rcx.\n");
		}

		sStackWalkList results[0x20];
		RtlZeroMemory(&results[0], sizeof(results));
		walk_stack_thread(ThreadObj, &results[0]);
		for (int i = 0; i < 0x20; i++) {
			if (results[i].Rsp == 0)
				break;
			if (is_address_outside_of_module_list(pModuleList, results[i].Rip)) {
				DbgPrint("[FLAG/DETECTION] Stack Scan found Address outside of module list.\n");
				scan_bigpool_check_1(results[i].Rip);
			}
			//print_module_name(pModuleList, results[i].Rip);
			//DbgPrint("stack walk found %p\n---------------\n", results[i].Rip);
		}

	}
	
}

typedef struct _UNLOADED_DRIVERS {
	UNICODE_STRING Name;
	PVOID StartAddress;
	PVOID EndAddress;
	LARGE_INTEGER CurrentTime;
} UNLOADED_DRIVERS, *PUNLOADED_DRIVERS;

extern "C" PUNLOADED_DRIVERS MmUnloadedDrivers;

void check_unloaded()
{
	//to-do
}

struct PiDDBCacheEntry
{
	LIST_ENTRY		List;
	UNICODE_STRING	DriverName;
	ULONG			TimeDateStamp;
	NTSTATUS		LoadStatus;
	char			_0x0028[16]; // data from the shim engine, or uninitialized memory for custom drivers
};

EXTERN_C PVOID ResolveRelativeAddress(
	_In_ PVOID Instruction,
	_In_ ULONG OffsetOffset,
	_In_ ULONG InstructionSize
)
{
	ULONG_PTR Instr = (ULONG_PTR)Instruction;
	LONG RipOffset = *(PLONG)(Instr + OffsetOffset);
	PVOID ResolvedAddr = (PVOID)(Instr + InstructionSize + RipOffset);

	return ResolvedAddr;
}

UCHAR PiDDBLockPtr_sig[] = "\x48\x8D\x0D\x00\x00\x00\x00\xE8\x00\x00\x00\x00\x4C\x8B\x8C";
UCHAR PiDDBCacheTablePtr_sig[] = "\x66\x03\xD2\x48\x8D\x0D";
//you can also put the sig within the function, but some of the sig ends up on the stack and in the .text section, and causes issues when zeroing the sig memory.

extern "C" bool LocatePiDDB(PERESOURCE* lock, PRTL_AVL_TABLE* table)
{
	PVOID PiDDBLockPtr = nullptr, PiDDBCacheTablePtr = nullptr;
	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBLockPtr_sig, 0, sizeof(PiDDBLockPtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBLockPtr)))) {
		DbgPrintEx(0, 0, xorstr_("Unable to find PiDDBLockPtr sig.\n"));
		return false;
	}

	if (!NT_SUCCESS(BBScanSection("PAGE", PiDDBCacheTablePtr_sig, 0, sizeof(PiDDBCacheTablePtr_sig) - 1, reinterpret_cast<PVOID*>(&PiDDBCacheTablePtr)))) {
		DbgPrintEx(0, 0, xorstr_("Unable to find PiDDBCacheTablePtr sig.\n"));
		return false;
	}
	
	PiDDBCacheTablePtr = PVOID((uintptr_t)PiDDBCacheTablePtr + 3);

	*lock = (PERESOURCE)(ResolveRelativeAddress(PiDDBLockPtr, 3, 7));
	*table = (PRTL_AVL_TABLE)(ResolveRelativeAddress(PiDDBCacheTablePtr, 3, 7));

	return true;
}

void check_piddb()
{
	PERESOURCE PiDDBLock; PRTL_AVL_TABLE table;
	if (!LocatePiDDB(&PiDDBLock, &table)) {
		DbgPrint("sig scanning failed.\n");
		return;
	}
	ExAcquireResourceExclusiveLite(PiDDBLock, TRUE);

	for (PiDDBCacheEntry* p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(table, TRUE);
		p != NULL;
		p = (PiDDBCacheEntry*)RtlEnumerateGenericTableAvl(table, FALSE)) {
		if (p->TimeDateStamp == 0x5284eac3)
			DbgPrint("[DETECTION] kdmapper detected, driver: %wZ\n", p->DriverName);
		if (p->TimeDateStamp == 0x57CD1415)
			DbgPrint("[DETECTION] drvmap detected, driver: %wZ\n", p->DriverName);
	}

	ExReleaseResourceLite(PiDDBLock);
}

void check()
{
	auto pModuleList = GetKernelModuleList();
	DbgPrint("Scanning system threads\n");
	scan_system_threads(pModuleList);
	DbgPrint("Finished scanning system threads\n");
	
	DbgPrint("Scanning bigpool\n");
	scan_bigpool_check_2();
	DbgPrint("Finished scanning bigpool\n");

	DbgPrint("Scanning PiDDBCacheTable\n");
	check_piddb();
	DbgPrint("scanned PiDDBCacheTable\n");

	ExFreePoolWithTag(pModuleList, POOL_TAG);
}

DRIVER_UNLOAD MyUnload;

_Use_decl_annotations_
VOID
MyUnload(
	struct _DRIVER_OBJECT  *DriverObject
)
{
	// Function body
}

EXTERN_C
NTSTATUS
NTAPI
DriverEntry(
	_In_ PDRIVER_OBJECT DriverObject,
	_In_ PUNICODE_STRING RegistryPath
)
{
	//UNREFERENCED_PARAMETER(DriverObject);
	UNREFERENCED_PARAMETER(RegistryPath);

	DriverObject->DriverUnload = MyUnload;

	DbgPrint("(KERNEL) anti-cheat simulator v1\r\n");
	
	HANDLE hThread;
	PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)&check, NULL);
	ZwClose(hThread);

	return true;
}