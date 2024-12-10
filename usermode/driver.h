#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <cstdint>
#include <intrin.h>
#include "check.h"


uintptr_t guarded_region;
uintptr_t custom_cr3r;
uintptr_t pml4_basem;
uintptr_t PML4BASEE;

#define read_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x13AC, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define base_addy_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x14AC, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)
#define cr3_van_ctl CTL_CODE(FILE_DEVICE_UNKNOWN, 0x12AC, METHOD_BUFFERED, FILE_SPECIAL_ACCESS)

typedef struct _r {
	INT32 Security;
	INT32 ProcessId;
	ULONGLONG Address;
	ULONGLONG Buffer;
	ULONGLONG Size;
	BOOLEAN Write;
	
} r, * pr;

typedef struct _b {
	INT32 Security;
	INT32 ProcessId;
	ULONGLONG* Address;
} b, * pb;

//guarded region struct
typedef struct _gr {
	ULONGLONG* guarded;
} gr, * pgr;


namespace driver {
	HANDLE DriverHandle;
	INT32 ProcessIdentifier;

	bool Init() {
		DriverHandle = CreateFileW((L"\\\\.\\\SLIGHTSPASTED"), GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

		if (!DriverHandle || (DriverHandle == INVALID_HANDLE_VALUE))
			return false;

		return true;
	}

	void ReadPhysical(PVOID address, PVOID buffer, DWORD size) {
		_r arguments = { 0 };

		arguments.Address = (ULONGLONG)address;
		arguments.Buffer = (ULONGLONG)buffer;
		arguments.Size = size;
		arguments.ProcessId = ProcessIdentifier;
		arguments.Write = FALSE;
		

		DeviceIoControl(DriverHandle, read_ctl, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);
	}

	uintptr_t GetBaseAddress() {
		uintptr_t image_address = { NULL };
		_b arguments = { NULL };

		arguments.ProcessId = ProcessIdentifier;
		arguments.Address = (ULONGLONG*)&image_address;

		DeviceIoControl(DriverHandle, base_addy_ctl, &arguments, sizeof(arguments), nullptr, NULL, NULL, NULL);

		return image_address;
	}

	auto get_guarded() -> uintptr_t
	{
		uintptr_t shadow_g = { NULL };
		_gr input = { 0 };

		input.guarded = (ULONGLONG*)&shadow_g;

		DeviceIoControl(DriverHandle, cr3_van_ctl, &input, sizeof(input), nullptr, NULL, NULL, NULL);

		return shadow_g;
	}

	INT32 FindProcessID(LPCTSTR process_name) {
		PROCESSENTRY32 pt;
		HANDLE hsnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
		pt.dwSize = sizeof(PROCESSENTRY32);
		if (Process32First(hsnap, &pt)) {
			do {
				if (!lstrcmpi(pt.szExeFile, process_name)) {
					CloseHandle(hsnap);
					ProcessIdentifier = pt.th32ProcessID;
					return pt.th32ProcessID;
				}
			} while (Process32Next(hsnap, &pt));
		}
		CloseHandle(hsnap);

		return { NULL };
	}
}

template <typename T>
T read(uint64_t address) {
	T buffer{ };
	driver::ReadPhysical((PVOID)address, &buffer, sizeof(T));
	return buffer;
}

template <typename T>
T readguarded(uint64_t address) {
	//SPOOF_FUNC;
	T buffer{ };
	driver::ReadPhysical((PVOID)address, &buffer, sizeof(T));
	if (check::is_guarded(buffer))
	{
		buffer = check::validate_pointer(buffer);
	}

	return buffer;
}

bool IsValid(const uint64_t adress)
{
	if (adress <= 0x400000 || adress == 0xCCCCCCCCCCCCCCCC || reinterpret_cast<void*>(adress) == nullptr || adress >
		0x7FFFFFFFFFFFFFFF) {
		return false;
	}
	return true;
}
template<typename T>
bool ReadArray(uintptr_t address, T out[], size_t len)
{
	for (size_t i = 0; i < len; ++i)
	{
		out[i] = read<T>(address + i * sizeof(T));
	}
	return true; // you can add additional checks to verify successful reads
}

template<typename T>
bool ReadArray2(uint64_t address, T* out, size_t len)
{
	if (!driver::DriverHandle || driver::DriverHandle == INVALID_HANDLE_VALUE)
	{
		if (!driver::Init())
		{
			return false;
		}
	}

	if (!out || len == 0)
	{
		return false;
	}

	for (size_t i = 0; i < len; ++i)
	{
		if (!IsValid(address + i * sizeof(T)))
		{
			return false;
		}

		out[i] = read<T>(address + i * sizeof(T));
	}
	return true;
}

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)

typedef struct _SYSTEM_BIGPOOL_ENTRY
{
	union {
		PVOID VirtualAddress;
		ULONG_PTR NonPaged : 1;
	};
	ULONG_PTR SizeInBytes;
	union {
		UCHAR Tag[4];
		ULONG TagUlong;
	};
} SYSTEM_BIGPOOL_ENTRY, * PSYSTEM_BIGPOOL_ENTRY;

typedef struct _SYSTEM_BIGPOOL_INFORMATION {
	ULONG Count;
	SYSTEM_BIGPOOL_ENTRY AllocatedInfo[ANYSIZE_ARRAY];
} SYSTEM_BIGPOOL_INFORMATION, * PSYSTEM_BIGPOOL_INFORMATION;

typedef enum _SYSTEM_INFORMATION_CLASSS {
	SystemBigPoolInformation = 0x42
} SYSTEM_INFORMATION_CLASSS;

typedef NTSTATUS(WINAPI* pNtQuerySystemInformation)(
	IN _SYSTEM_INFORMATION_CLASSS SystemInformationClass,
	OUT PVOID                   SystemInformation,
	IN ULONG                    SystemInformationLength,
	OUT PULONG                  ReturnLength
	);

__forceinline auto query_bigpools() -> PSYSTEM_BIGPOOL_INFORMATION
{
	static const pNtQuerySystemInformation NtQuerySystemInformation =
		(pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQuerySystemInformation");

	DWORD length = 0;
	DWORD size = 0;
	LPVOID heap = HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, 0);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, 0xFF);
	NTSTATUS ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, 0x30, &length);
	heap = HeapReAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, heap, length + 0x1F);
	size = length;
	ntLastStatus = NtQuerySystemInformation(SystemBigPoolInformation, heap, size, &length);

	return reinterpret_cast<PSYSTEM_BIGPOOL_INFORMATION>(heap);
}

typedef struct ShadowRegionsDataStructure
{
	uintptr_t OriginalPML4_t;
	uintptr_t ClonedPML4_t;
	uintptr_t GameCr3;
	uintptr_t ClonedCr3;
	uintptr_t FreeIndex;
} ShadowRegionsDataStructure;

struct ShadowData {
	uintptr_t DecryptedClonedCr3;
	uintptr_t PML4BASE;
};

uintptr_t KernelModule(std::string& module_name)
{

	static const pNtQuerySystemInformation NtQuerySystemInformation =
		(pNtQuerySystemInformation)GetProcAddress(GetModuleHandleA(("ntdll.dll")), ("NtQuerySystemInformation"));

	struct s_process_module_information
	{
		HANDLE section;
		std::uint64_t mapped_base;
		std::uint64_t image_base;
		std::uint32_t image_size;
		std::uint32_t flags;
		std::uint16_t load_order_index;
		std::uint16_t init_order_index;
		std::uint16_t load_count;
		std::uint16_t offset;
		std::uint8_t full_path_name[256];
	};

	struct s_process_modules
	{
		std::uint32_t numer_of_modules;
		s_process_module_information modules[1];
	};

	std::uint32_t size = 0;
	NtQuerySystemInformation(static_cast<_SYSTEM_INFORMATION_CLASSS>(0x0B), nullptr, 0, reinterpret_cast<PULONG>(&size));

	if (!size)
	{
		return 0;
	}

	std::uint32_t buffer_size = size;
	s_process_modules* process_modules = static_cast<s_process_modules*>(VirtualAlloc(nullptr, buffer_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));

	if (!process_modules)
	{
		return 0;
	}

	if (!NT_SUCCESS(NtQuerySystemInformation(static_cast<_SYSTEM_INFORMATION_CLASSS>(0x0B), process_modules, buffer_size, reinterpret_cast<PULONG>(&size))))
	{
		VirtualFree(process_modules, 0, MEM_RELEASE);
		return 0;
	}

	std::uint64_t image_base = 0;

	for (std::uint32_t i = 0; i < process_modules->numer_of_modules; i++)
	{
		s_process_module_information* module = &process_modules->modules[i];

		std::string current_module_name(reinterpret_cast<char*>(module->full_path_name + module->offset));

		if (module_name == current_module_name)
		{
			image_base = module->image_base;
			break;
		}
	}

	VirtualFree(process_modules, 0, MEM_RELEASE);
	return image_base;
}

uintptr_t decryptClonedCr3e(ShadowRegionsDataStructure SR)
{
	std::string ud = ("vgk.sys");
	uintptr_t vgk = KernelModule(ud);

	BYTE byte_83E60 = read<BYTE>(vgk + 0x83E60);
	uint64_t qword_83F20 = read<uint64_t>(vgk + 0x83F20);

	uintptr_t v5 = (0x49B74B6480000000i64 * SR.ClonedCr3
		+ 0xC2D8B464B4418C6Cui64 * ~(unsigned __int64)(unsigned __int8)byte_83E60
		+ 0x66B8CDC1FFFFFFFFi64 * (unsigned __int8)byte_83E60
		+ 0x5C1FE6A2B4418C6Di64
		* ((unsigned __int8)(byte_83E60 & SR.ClonedCr3) - (SR.ClonedCr3 | ~(unsigned __int64)(unsigned __int8)byte_83E60)))
		* ((SR.ClonedCr3 ^ (unsigned __int8)byte_83E60)
			+ -2 * ((unsigned __int8)byte_83E60 ^ (SR.ClonedCr3 | (unsigned __int8)byte_83E60))
			+ 2
			* ((((unsigned __int8)byte_83E60 | 0xE8i64) ^ 0xFFFFFFFFFFFFFF17ui64)
				+ (~SR.ClonedCr3 | (unsigned __int8)byte_83E60 ^ 0xE8i64))
			- ((unsigned __int8)byte_83E60 ^ (unsigned __int64)~SR.ClonedCr3 ^ 0xE8)
			+ -3 * ~SR.ClonedCr3
			- 232);

	uintptr_t v6 = ((SR.ClonedCr3 ^ (SR.ClonedCr3 * (0x13D0F34E00000000i64 * SR.ClonedCr3 + 0x483C4F8900000000i64))) << 63)
		+ SR.ClonedCr3
		* (0x7D90DC33C620C593i64 * (0x13D0F34E00000000i64 * SR.ClonedCr3 + 0x483C4F8900000000i64)
			+ 0x8000000000000000ui64)
		+ (SR.ClonedCr3
			* (0x55494E5B80000000i64 * qword_83F20
				+ 0xC83B18136241A38Dui64 * ~qword_83F20
				+ 0xCE3CE5E180000000ui64 * ~SR.ClonedCr3
				+ 0x72F1C9B7E241A38Di64 * ((qword_83F20 | 0xE8) - (231i64 - ((unsigned __int8)qword_83F20 & 0xE8))))
			+ 0x71C31A1E80000000i64)
		* (0x99BF7D2380CF6EC3ui64 * qword_83F20
			+ 0x664082DC7F30913Ei64 * (SR.ClonedCr3 | (unsigned __int8)byte_83E60)
			+ 0x19BF7D2380CF6EC2i64 * ~qword_83F20
			+ 0xE64082DC7F30913Eui64 * (~SR.ClonedCr3 & ~(unsigned __int64)(unsigned __int8)byte_83E60)
			+ ((SR.ClonedCr3
				+ ((unsigned __int8)byte_83E60 & (qword_83F20 ^ SR.ClonedCr3))
				+ (qword_83F20 | (unsigned __int8)byte_83E60)) << 63));

	uintptr_t decrypted_cloned_cr3 =
		0x137FEEF6AB38CFB4i64 * v5
		+ ((~v5 ^ ~((0x8000000000000001ui64 * qword_83F20
			+ 0x2FDBF65F8A4AC9C9i64 * SR.ClonedCr3
			+ ((qword_83F20 ^ SR.ClonedCr3) << 63)
			+ 0x502409A075B53637i64 * SR.ClonedCr3)
			* (0xFD90DC33C620C592ui64
				* ~(SR.ClonedCr3 * (0x13D0F34E00000000i64 * SR.ClonedCr3 + 0x483C4F8900000000i64))
				+ v6
				+ 0x2183995CC620C592i64))) << 63)
		+ 0x6C80110954C7304Di64 * ((v5 & qword_83F20) - (~qword_83F20 & ~v5) - qword_83F20)
		- 0x7FFFFFFFFFFFFFFFi64
		* (0x8000000000000001ui64 * qword_83F20
			+ 0x2FDBF65F8A4AC9C9i64 * SR.ClonedCr3
			+ ((qword_83F20 ^ SR.ClonedCr3) << 63)
			+ 0x502409A075B53637i64 * SR.ClonedCr3)
		* (0xFD90DC33C620C592ui64 * ~(SR.ClonedCr3 * (0x13D0F34E00000000i64 * SR.ClonedCr3 + 0x483C4F8900000000i64))
			+ v6
			+ 0x2183995CC620C592i64)
		- 0x4F167C5CD4C7304Ei64;

	return decrypted_cloned_cr3;
}

inline ShadowData GetVGKShadowData(uintptr_t VgkAddress) {

    ShadowRegionsDataStructure Data = read<ShadowRegionsDataStructure>(VgkAddress + 0x83D98);

	printf(("\n\nOriginalPML4_t: 0x%p \n"), Data.OriginalPML4_t);
	printf(("ClonedPML4_t: 0x%p \n"), Data.ClonedPML4_t);

	printf(("GameCr3: 0x%p \n"), Data.GameCr3);
	printf(("ClonedCr3: 0x%p \n"), Data.ClonedCr3);
	printf(("Free Index: 0x%p \n"), Data.FreeIndex);

	uintptr_t DecryptedCr3 = decryptClonedCr3e(Data);
	printf(("Decrypted Cr3: 0x%p \n"), DecryptedCr3);
	custom_cr3r = DecryptedCr3;
	pml4_basem = Data.FreeIndex << 0x27;

	return ShadowData{ custom_cr3r, pml4_basem };
}