#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <string>
#include <memory>
#include <algorithm>

/*

	I commented the perhaps "interesting" parts of the code.

*/

DWORD get_parent_pid(DWORD pid)
{
	DWORD return_pid = 0;

	PROCESSENTRY32 pe = {};
	pe.dwSize = sizeof(pe);

	HANDLE handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (handle && handle != INVALID_HANDLE_VALUE)
	{
		if (Process32First(handle, &pe))
		{
			do
			{
				if (pe.th32ProcessID == pid)
				{
					return_pid = pe.th32ParentProcessID;
					break;
				}

			} while (Process32Next(handle, &pe));
		}

		CloseHandle(handle);
	}

	return return_pid;
}

uintptr_t get_module_base_address(DWORD process_id, std::string_view module_name)
{
	uintptr_t module_base_address = 0;
	HANDLE snap_shot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, process_id);
	if (snap_shot_handle != INVALID_HANDLE_VALUE)
	{
		MODULEENTRY32 module_entry;
		module_entry.dwSize = sizeof(module_entry);
		if (Module32First(snap_shot_handle, &module_entry))
		{
			do
			{
				if (!strcmp(module_entry.szModule, module_name.data()))
				{
					module_base_address = (uintptr_t)module_entry.modBaseAddr;
					break;
				}
			} while (Module32Next(snap_shot_handle, &module_entry));
		}

		CloseHandle(snap_shot_handle);
	}

	return module_base_address;
}

uintptr_t find_address_for_patch(HANDLE handle, uintptr_t base)
{
	// this essentially is just a remote pattern scanner, but made a bit more interesting using c++ functions
	// a more conventional method would be like so: 
	// https://github.com/hinnie123/csgo-load-library-bypass-injector/blob/master/csgo-load-library-bypass-injector.cpp#L33

	IMAGE_DOS_HEADER dos_header;
	IMAGE_NT_HEADERS nt_headers;

	// reading dos and nt headers so we can get the size of the image
	ReadProcessMemory(handle, (void*)base, &dos_header, sizeof(dos_header), nullptr);
	ReadProcessMemory(handle, (void*)(base + dos_header.e_lfanew), &nt_headers, sizeof(nt_headers), nullptr);

	// now using the size of the image, we're reading the complete image into this "smart" buffer (it will dealloc when exiting the function)
	std::unique_ptr<uint8_t[]> local_image(new uint8_t[nt_headers.OptionalHeader.SizeOfImage]);
	ReadProcessMemory(handle, (void*)base, local_image.get(), nt_headers.OptionalHeader.SizeOfImage, nullptr);

	// so now we can loop over the sections as if we were internal, because we read the process image into our process
	IMAGE_SECTION_HEADER* sections = IMAGE_FIRST_SECTION((IMAGE_NT_HEADERS*)(local_image.get() + dos_header.e_lfanew));

	// finding .text section
	auto section = std::find_if(sections, sections + nt_headers.FileHeader.NumberOfSections, [&](const auto& s) {
		return std::equal(s.Name, s.Name + 5, ".text");
	});

	// finding this pattern: 41 80 38 00 74 0D
	byte pattern[6] = { 0x41, 0x80, 0x38, 0x00, 0x74, 0x0d };

	// using the std::search algorithm
	uintptr_t local_address = 
		(uintptr_t)std::search(local_image.get(), local_image.get() + section->Misc.VirtualSize, pattern, pattern + sizeof(pattern));

	// because the result is only for the "image" we read into our process, we will have to translate it into the address for the remote process
	// so, find the offset, and finally add the offset to the actual image base address
	uintptr_t offset = local_address - (uintptr_t)local_image.get();
	return base + offset;
}

void do_queue_bypass(HANDLE handle, DWORD pid)
{
	// this can be done inside a cheat without patching .text
	// but we fully disabled the anticheat anyway, so why not?
	// besides, people could learn a thing or two from this

	/*

	*	.text:0000000140D865BA 41 80 38 00             cmp     byte ptr [r8], 0             // this is always 0 when you're in the queue
	*	.text:0000000140D865BE 74 0D                   jz      short somewhere_after_login  // so it will always jump over the login function
		.text:0000000140D865C0 48 8B 09                mov     rcx, [rcx]                   // so we're just going to patch the cmp and jz out
		.text:0000000140D865C3 E8 E8 0F 02 00          call    login_fn                     // so it will always call the login_fn

	*/

	uintptr_t base_address = get_module_base_address(pid, "PortalWars-Win64-Shipping.exe");
	if (!base_address)
		return;

	// the address we find will point to the beginning of the highlighted instructions above
	uintptr_t address = find_address_for_patch(handle, base_address);
	if (address == base_address)
		return;

	// changing the protection so we can write to the adress inside the .text section
	DWORD old_protection;
	VirtualProtectEx(handle, (void*)address, 6, PAGE_READWRITE, &old_protection);

	// now change the bytes to NOPs, the NOP instruction will do nothing
	byte new_bytes[6] = { 0x90, 0x90, 0x90, 0x90, 0x90, 0x90 };
	WriteProcessMemory(handle, (void*)address, new_bytes, sizeof(new_bytes), nullptr);

	// changing the protection back
	VirtualProtectEx(handle, (void*)address, 6, old_protection, &old_protection);

	std::cout << "Succesfully applied queue bypass." << std::endl;
}

void inject_dll(HANDLE handle, std::string_view dll_path)
{
	// allocating memory inside of the process where we can write the dll path into
	void* dll_path_addr = VirtualAllocEx(handle, 0, dll_path.size(), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!dll_path_addr)
		return;

	// writing the dll path into the allocated memory
	if (!WriteProcessMemory(handle, dll_path_addr, dll_path.data(), dll_path.size(), nullptr))
		return;

	// starting a remote thread that will call LoadLibraryA with the address of the dll path as argument
	// essentially calling LoadLibraryA("C:/some/cheat/path.dll") from inside the process
	HANDLE remote_thread = CreateRemoteThread(handle, nullptr, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, dll_path_addr, 0, nullptr);
	if (!remote_thread)
		return;

	// waiting for the thread to finish it's job
	WaitForSingleObject(remote_thread, INFINITE);
	std::cout << "Succesfully injected dll." << std::endl;
}

int main(int argc, char** argv)
{
	if (argc < 2)
	{
		std::cout << "Drag and drop the dll you want to inject onto the injector." << std::endl;
		Sleep(3000);
		return 0;
	}

	std::string dll_path = argv[1];

	HWND splitgate_hwnd = FindWindowA(0, "PortalWars  ");
	if (splitgate_hwnd)
	{
		std::cout << "Please close Splitgate before attempting to use the injector." << std::endl;
		Sleep(3000);
		return 0;
	}

	std::cout << "Start the game now..." << std::endl;

	while (!splitgate_hwnd)
	{
		splitgate_hwnd = FindWindowA(0, "PortalWars  ");
		Sleep(100);
	}

	std::cout << "Splitgate found." << std::endl;

	DWORD splitgate_pid = 0;
	GetWindowThreadProcessId(splitgate_hwnd, &splitgate_pid);

	if (!splitgate_pid)
		return 0;

	DWORD equ8_anticheat_pid = get_parent_pid(splitgate_pid);
	while (!equ8_anticheat_pid)
		equ8_anticheat_pid = get_parent_pid(splitgate_pid);

	HANDLE equ8_handle = OpenProcess(PROCESS_TERMINATE, false, equ8_anticheat_pid);
	if (!equ8_handle)
		return 0;

	TerminateProcess(equ8_handle, 0);
	CloseHandle(equ8_handle);

	std::cout << "Making sure equ8 has been terminated." << std::endl;

	// wait for the anticheat to terminate
	Sleep(5000);

	// now we can continue our operations as you would normally
	{
		HANDLE splitgate_handle = OpenProcess(PROCESS_ALL_ACCESS, false, splitgate_pid);
		if (!splitgate_handle)
			return 0;

		std::cout << "Opened handle to Splitgate." << std::endl;

		do_queue_bypass(splitgate_handle, splitgate_pid);
		inject_dll(splitgate_handle, dll_path);

		CloseHandle(splitgate_handle);
	}

	std::cout << "Bye :)" << std::endl;
	Sleep(1000);

	return 0;
}
