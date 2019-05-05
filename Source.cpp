#include <ntifs.h>
#include <ntddk.h>
extern "C" {
#include "NativeStructs.h"
}
#include "defs.h"
#include "hyperdetect.h"

#define xorstr_(x) x

#define POOL_TAG 'enoN'

void sleep(LONG milliseconds)
{
	LARGE_INTEGER interval;
	interval.QuadPart = -(10000ll * milliseconds);

	KeDelayExecutionThread(KernelMode, FALSE, &interval);
}


NTSTATUS BBSearchPattern(IN PCUCHAR pattern, IN UCHAR wildcard, IN ULONG_PTR len, IN const VOID* base, IN ULONG_PTR size, OUT PVOID* ppFound, int index = 0)
{
	ASSERT(ppFound != NULL && pattern != NULL && base != NULL);
	if (ppFound == NULL || pattern == NULL || base == NULL)
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER;
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
		return STATUS_ACCESS_DENIED; //STATUS_INVALID_PARAMETER

	if (nullptr == base)
		base = GetKernelBase();
	if (base == nullptr)
		return STATUS_ACCESS_DENIED; //STATUS_NOT_FOUND;

	PIMAGE_NT_HEADERS64 pHdr = RtlImageNtHeader(base);
	if (!pHdr)
		return STATUS_ACCESS_DENIED; // STATUS_INVALID_IMAGE_FORMAT;

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
				/*if (auto page = MmMapIoSpaceEx(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, PAGE_READWRITE)) {
					
					MmUnmapIoSpace(page, PAGE_SIZE);
				}
				*/

				//https://www.unknowncheats.me/forum/2427433-post12.html
				if (pBuf->AllocatedInfo[i].TagUlong == 'SldT') {
					DbgPrint("[FLAG] TdlS pooltag detected\n");
					if (auto page = MmMapIoSpaceEx(MmGetPhysicalAddress((void*)pBuf->AllocatedInfo[i].VirtualAddress), PAGE_SIZE, PAGE_READWRITE)) {
						if (*(PULONG)((uintptr_t)page + 0x184) == 0x0B024BC8B48)
							DbgPrint("[DETECTION] 0x0B024BC8B48 found at pool + 0x184\n");
						//to-do: also hash the memory(with custom crc32 table) and check for 0C8931AEBh

						MmUnmapIoSpace(page, PAGE_SIZE);
					}
				}

				/*
				pooltags checked:
				 if ( *(v3 - 1) != 'rcIC' || *v3 <= v3[1] )
        {
          if ( *(v3 - 1) == 'csIC' && *v3 > v3[1] )

		  if these pooltags do not exist, code integrity is disabled(maybe this occurs due to UPGDSED, which disables the initialization of CI?)
				*/
				
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

static inline unsigned long long rdtsc_diff_vmexit() {
	auto t1 = __rdtsc();
	int r[4];
	__cpuid(r, 1);
	return __rdtsc() - t1;
}

int cpu_rdtsc_force_vmexit() {
	int i;
	unsigned long long avg = 0;
	for (i = 0; i < 10; i++) {
		avg = avg + rdtsc_diff_vmexit();
		sleep(500);
	}
	avg = avg / 10;
	return (avg < 1000 && avg > 0) ? FALSE : TRUE;
}

bool detect_hypervisor()
{
	if (cpu_rdtsc_force_vmexit()) {
		DbgPrint("Detected hypervisor through a timing attack\n");
		return true;
	}

	__try {
		__vmx_vmread(NULL, nullptr);
		DbgPrint("Detected hypervisor through vmread\n");
	}
	__except (EXCEPTION_EXECUTE_HANDLER) {

	}
	return false;
}

#pragma pack(push, 4)
#define POBJECT PVOID

typedef struct _SYSTEM_HANDLE
{
	ULONG 	uIdProcess;
	UCHAR 	ObjectType;
	UCHAR 	Flags;
	USHORT 	Handle;
	POBJECT 	pObject;
	ACCESS_MASK 	GrantedAccess;
}SYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_INFORMATION {
	ULONG			uCount;
	SYSTEM_HANDLE	Handles[ANYSIZE_ARRAY];
} SYSTEM_HANDLE_INFORMATION, *PSYSTEM_HANDLE_INFORMATION;

#pragma pack(pop)

PSYSTEM_HANDLE_INFORMATION GetHandleList()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	//ZwQuerySystemInformation(SystemHandleInformation, &neededSize, 0, &neededSize); //returns incorrect size for whatever reason -- don't use.
	neededSize = 8 * 1024 * 1024;

	PSYSTEM_HANDLE_INFORMATION pHandleList;

	if (pHandleList = (PSYSTEM_HANDLE_INFORMATION)ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {

		NTSTATUS r;
		if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemHandleInformation, pHandleList, neededSize, 0)))
			return pHandleList;
		else
			DbgPrint("r = %x\n", r);
	}
	return nullptr;
}


void check_physical_memory_handles()
{
	auto handles = GetHandleList();
	if (!handles) {
		DbgPrint("Unable to obtain handle list\n");
		return;
	}
	UNICODE_STRING phys_mem_str;
	OBJECT_ATTRIBUTES oaAttributes;
	RtlInitUnicodeString(&phys_mem_str, xorstr_(L"\\Device\\PhysicalMemory"));
	InitializeObjectAttributes(&oaAttributes, &phys_mem_str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	HANDLE hPhysMem;
	auto ntStatus = ZwOpenSection(&hPhysMem, SECTION_ALL_ACCESS, &oaAttributes);

	PVOID Object;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(hPhysMem, 1, nullptr, KernelMode, &Object, nullptr))) {
		DbgPrint("Unablle to get PhyiscalMemory object.\n");
		ExFreePoolWithTag(handles, POOL_TAG);
		ZwClose(hPhysMem);
		return;
	}

	ZwClose(hPhysMem);

	__try {
		for (ULONG i = 0; i < handles->uCount; i++) {
			if (handles->Handles[i].uIdProcess == 4)
				continue; //ignore system process for detection.
			if (handles->Handles[i].pObject == Object) { //is PhysicalMemory object?
				//DbgPrint("found physmem handle\n");
				 if (!ObIsKernelHandle((HANDLE)handles->Handles[i].Handle))
					DbgPrint("[DETECTION] Usermode PhysicalMemory handle detected, pid = %d, access = 0x%x.\n", handles->Handles[i].uIdProcess, handles->Handles[i].GrantedAccess);
			}
		}
	} __except (EXCEPTION_EXECUTE_HANDLER) {
		DbgPrint("Unexpected AV in check_physical_memory_handles\n");
	}

	ObDereferenceObject(Object);

	ExFreePoolWithTag(handles, POOL_TAG);
}

PSYSTEM_PROCESS_INFO get_process_list()
{
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	neededSize = 8 * 1024 * 1024;

	PSYSTEM_PROCESS_INFO pProcessList;

	if (pProcessList = (decltype(pProcessList))ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {

		NTSTATUS r;
		if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemProcessInformation, pProcessList, neededSize, 0)))
			return pProcessList;
		else
			DbgPrint("r = %x\n", r);
	}
	return nullptr;

}

#include "page_table_defs.h"

void detect_perfect_injector()
{
	UNICODE_STRING phys_mem_str;
	OBJECT_ATTRIBUTES oaAttributes;
	RtlInitUnicodeString(&phys_mem_str, xorstr_(L"\\Device\\PhysicalMemory"));
	InitializeObjectAttributes(&oaAttributes, &phys_mem_str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	HANDLE hPhysMem;
	if (!NT_SUCCESS(ZwOpenSection(&hPhysMem, SECTION_ALL_ACCESS, &oaAttributes))) {
		DbgPrint("Failed to open phys mem section\n");
		return;
	}

	PVOID PhysicalMemoryBegin = NULL;

	auto Range = MmGetPhysicalMemoryRanges();
	DWORD64 PhysicalMemorySize = 0;

	while (Range->NumberOfBytes.QuadPart)
	{
		PhysicalMemorySize = max(PhysicalMemorySize, Range->BaseAddress.QuadPart + Range->NumberOfBytes.QuadPart);
		Range++;
	}

	if (!NT_SUCCESS(ZwMapViewOfSection(
		hPhysMem,
		ZwCurrentProcess(),
		&PhysicalMemoryBegin,
		NULL,
		NULL,
		nullptr,
		&PhysicalMemorySize,
		ViewUnmap,
		NULL,
		PAGE_READWRITE))) {
		DbgPrintEx(0, 0, "ZwMapViewOfSection failed.\n");
		ZwClose(hPhysMem);
		return;
	}

	auto processes = get_process_list();
	if (!processes) {
		DbgPrint("Unable to get process list.\n");
		ZwUnmapViewOfSection(ZwCurrentProcess(), PhysicalMemoryBegin);
		ZwClose(hPhysMem);
		return;
	}

	auto walk = processes;
	while (walk->NextEntryOffset)
	{
		/*if ((ULONG)walk->UniqueProcessId != 12132) {
			walk = (PSYSTEM_PROCESS_INFO)((uintptr_t)walk + walk->NextEntryOffset);
			continue;
		}*/

		//instead of reading cr3 from _EPROCESS::DirectoryBase you can obtain it by attaching to the process & __readcr3().
		KAPC_STATE apcState;

		PEPROCESS process = NULL;
		if (walk->UniqueProcessId != NULL)
		if (NT_SUCCESS(PsLookupProcessByProcessId(walk->UniqueProcessId, &process))) {

			__try {
				KeStackAttachProcess(process, &apcState);
				auto cr3 = __readcr3();
				KeUnstackDetachProcess(&apcState);

				PTE_CR3 Cr3 = { cr3 };

				auto system_range_start = VIRT_ADDR{ (uintptr_t)MmSystemRangeStart };
				
				//max value of 9 bits = 512
				for (int pml4_index = system_range_start.pml4_index; pml4_index < 512; pml4_index++)
				{
					uint64_t pml4_addr = PFN_TO_PAGE(Cr3.pml4_p) + sizeof(PML4E) * pml4_index;
					if (pml4_addr > PhysicalMemorySize)
						continue;
					auto pml4 = (PML4E*)((uintptr_t)PhysicalMemoryBegin + pml4_addr);
					if (pml4->present && pml4->user) {
						for (int pdpt_index = system_range_start.pdpt_index; pdpt_index < 512; pdpt_index++) {

							auto pdpte_addr = PFN_TO_PAGE(pml4->pdpt_p) + sizeof(PDPTE) * pdpt_index;
							if (pdpte_addr > PhysicalMemorySize)
								continue;

							auto pdpte = (PDPTE*)((uintptr_t)PhysicalMemoryBegin + pdpte_addr);
							if (!pdpte->present || !pdpte->user)
								continue;

							DbgPrint("[DETECTION] kernelmode memory mapped to usermode: %wZ\n", walk->ImageName);
						}

					}
				}
			}
			__except (EXCEPTION_EXECUTE_HANDLER) {
				DbgPrint("unexpected AV in detect PI\n");
			}
			ObDereferenceObject(process);
		}
		else
			DbgPrint("Unable to lookup _EPROCESS from PID %d\n", (ULONG)walk->UniqueProcessId);
		//DbgPrint("process: %ws checked\n", walk->ImageName.Buffer);

		walk = (PSYSTEM_PROCESS_INFO)((uintptr_t)walk + walk->NextEntryOffset); // Calculate the address of the next entry.
	}

	ExFreePoolWithTag(processes, POOL_TAG);
	ZwUnmapViewOfSection(ZwCurrentProcess(), PhysicalMemoryBegin);
	ZwClose(hPhysMem);
}

typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1 {
	struct _GUID BootIdentifier;
	enum _FIRMWARE_TYPE FirmwareType;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION_V1;

// Size=32
typedef struct _SYSTEM_BOOT_ENVIRONMENT_INFORMATION {
	struct _GUID BootIdentifier;
	enum _FIRMWARE_TYPE FirmwareType;
	unsigned __int64 BootFlags;
} SYSTEM_BOOT_ENVIRONMENT_INFORMATION, *PSYSTEM_BOOT_ENVIRONMENT_INFORMATION;

void get_boot_uuid()
{
	//SystemBootEnvironmentInformation(0x5a)
	NTSTATUS status = STATUS_SUCCESS;
	ULONG neededSize = 0;

	neededSize = PAGE_SIZE;

	PSYSTEM_BOOT_ENVIRONMENT_INFORMATION pBootInfo;

	if (pBootInfo = (decltype(pBootInfo))ExAllocatePoolWithTag(NonPagedPool, neededSize, POOL_TAG)) {

		NTSTATUS r;
		if (NT_SUCCESS(r = ZwQuerySystemInformation(SystemBootEnvironmentInformation, pBootInfo, neededSize, 0))) {
			DbgPrint("boot GUID: %08X-%04X-%04X-%02X%02X%02X%02X%02X%02X%02X%02X\n", pBootInfo->BootIdentifier.Data1, pBootInfo->BootIdentifier.Data2, pBootInfo->BootIdentifier.Data3, pBootInfo->BootIdentifier.Data4[0], pBootInfo->BootIdentifier.Data4[1], pBootInfo->BootIdentifier.Data4[2], pBootInfo->BootIdentifier.Data4[3], pBootInfo->BootIdentifier.Data4[4], pBootInfo->BootIdentifier.Data4[5], pBootInfo->BootIdentifier.Data4[6], pBootInfo->BootIdentifier.Data4[7]);
			ExFreePoolWithTag(pBootInfo, POOL_TAG);
		}
		else
			DbgPrint("r = %x\n", r);
	}
}

typedef struct _DIRECTORY_BASIC_INFORMATION {
	UNICODE_STRING ObjectName;
	UNICODE_STRING ObjectTypeName;
} DIRECTORY_BASIC_INFORMATION, *PDIRECTORY_BASIC_INFORMATION;

void check_driver_dispatch(PSYSTEM_MODULE_INFORMATION pModuleList)
{
	HANDLE hDir;
	UNICODE_STRING str;
	OBJECT_ATTRIBUTES oa;
	RtlInitUnicodeString(&str, xorstr_(L"\\Driver"));
	InitializeObjectAttributes(&oa, &str, OBJ_CASE_INSENSITIVE | OBJ_KERNEL_HANDLE, (HANDLE)NULL, (PSECURITY_DESCRIPTOR)NULL);
	if (!NT_SUCCESS(ZwOpenDirectoryObject(&hDir, DIRECTORY_QUERY, &oa))) {
		DbgPrint("Failed to open \\Driver directory object.\n");
		return;
	}
	
	PVOID Obj;
	if (!NT_SUCCESS(ObReferenceObjectByHandle(hDir, DIRECTORY_QUERY, nullptr, KernelMode, &Obj, nullptr))) {
		DbgPrint("ObReferenceObjectByHandle failed.\n");
		return;
	}
	NtClose(hDir);

	auto obj_type = ObGetObjectType(Obj);
	ObDereferenceObject(Obj);

	HANDLE h;
	if (!NT_SUCCESS(ObOpenObjectByName(&oa, obj_type, KernelMode, NULL, DIRECTORY_QUERY, nullptr, &h))) {
		DbgPrint("ObOpenObjectByName failed.\n");
		return;
	}
	
	auto dir_info = (PDIRECTORY_BASIC_INFORMATION)ExAllocatePoolWithTag(POOL_TYPE::NonPagedPool, PAGE_SIZE, POOL_TAG);
	ULONG    ulContext = 0;

	ULONG returned_bytes;
	
	while (NT_SUCCESS(ZwQueryDirectoryObject(h, dir_info, PAGE_SIZE, TRUE, FALSE, &ulContext, &returned_bytes))) {
		PDRIVER_OBJECT pObj;
		wchar_t wsDriverName[100] = L"\\Driver\\";
		wcscat(wsDriverName, dir_info->ObjectName.Buffer);
		UNICODE_STRING ObjName;
		ObjName.Length = ObjName.MaximumLength = wcslen(wsDriverName) * 2;
		ObjName.Buffer = wsDriverName;
		if (NT_SUCCESS(ObReferenceObjectByName(&ObjName, OBJ_KERNEL_HANDLE | OBJ_CASE_INSENSITIVE, NULL, NULL, *IoDriverObjectType, KernelMode, nullptr, (PVOID*)&pObj))) {
			//DbgPrint("%wZ\n", pObj->DriverName);

			if (is_address_outside_of_module_list(pModuleList, reinterpret_cast<uintptr_t>(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]))) {
				DbgPrint("[DETECTION] %wZ driver has spoofed driver dispatch\n", pObj->DriverName);
			}

			if (is_address_outside_of_module_list(pModuleList, (uintptr_t)pObj->DriverStart)) {
				DbgPrint("[DETECTION] %wZ driver has spoofed DriverStart\n", pObj->DriverName);
			}

			auto dd = reinterpret_cast<uintptr_t>(pObj->MajorFunction[IRP_MJ_DEVICE_CONTROL]);
			if (dd < (uintptr_t)pObj->DriverStart || dd >(uintptr_t)pObj->DriverStart + pObj->DriverSize) {
				DbgPrint("[DETECTION] %wZ driver has spoofed driver dispatch (2)\n", pObj->DriverName);
			}

			if (is_address_outside_of_module_list(pModuleList, reinterpret_cast<uintptr_t>(pObj->FastIoDispatch))) {
				DbgPrint("[DETECTION] %wZ driver has spoofed FastIoDispatch\n", pObj->DriverName);
			}

			ObDereferenceObject(pObj);
		}
		
	}


	ZwClose(h);
}

void check()
{
	get_boot_uuid(); //checking if i've spoofed it properly.
	
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

	if (is_lazy_hypervisor_running()) //https://gist.github.com/drew0709/d31840bebbbb1ff1d112a6f46e162c05
		DbgPrint("lazy hypervisor detected\n");
	if (!detect_hypervisor())
		DbgPrint("HV not detected\n");

	check_physical_memory_handles();

	detect_perfect_injector();

	check_driver_dispatch(pModuleList);
	DbgPrint("scanned driver dispatch\n");

	ExFreePoolWithTag(pModuleList, POOL_TAG);

	DbgPrint("Scan routine finished!\n");
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

	DbgPrint("(KERNEL) anti-cheat simulator v2\n");
	
	HANDLE hThread;
	if (NT_SUCCESS(PsCreateSystemThread(&hThread, STANDARD_RIGHTS_ALL, NULL, NULL, NULL, (PKSTART_ROUTINE)&check, NULL)))
		ZwClose(hThread);
	else
		DbgPrint("Failed to create check thread.\n");

	return true;
}