#include <Windows.h>
#include <iostream>
#include "driver.h"
#include "thread"
namespace offsets
{
	WORD uworld = 0x60;
}


auto cachethread() -> void
{

	driver::get_guarded();

	/// USERMODE TO CHECK Shadow Region Data IGNORE THIS (Already have In Kernel) it wont work if you use this
	std::string ud = ("vgk.sys");
	uintptr_t vgk = KernelModule(ud);
	ShadowData shadowData = GetVGKShadowData(vgk);
	PML4BASEE = shadowData.PML4BASE;

	//PML4BASE KERNEL MODE
	auto pml4base = driver::get_guarded();
	printf("pml4base: 0x%p\n", pml4base);

	auto base = driver::GetBaseAddress();
	printf("base address: 0x%p\n", base);


	while (true)
	{
		auto uworld = read<uintptr_t>(pml4base + 0x60);
		printf("uworld: 0x%p\n", uworld);

		auto gameinstance = read<uintptr_t>(uworld + 0x1A0);
		printf("gameinstance: 0x%p\n", gameinstance);

		auto local_players = read<uintptr_t>(gameinstance + 0x40);
		printf("LocalPlayers: 0x%p\n", local_players);

		Sleep(5000);
	}
}

auto main() -> const NTSTATUS
{
	auto process = driver::FindProcessID(L"VALORANT-Win64-Shipping.exe");

	printf("processid: %i\n", process);

	if (process != 0)
	{
		driver::Init();

		std::thread(cachethread).detach();
	}

	getchar();
	return 0;
}