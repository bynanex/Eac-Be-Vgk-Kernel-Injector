﻿#pragma once
#include "driver.hpp"
#include "utils.h"
#include "spoof.h"
#include "lazy.h"
#include "skcrypt.h"
#include "auth.hpp"
#include "protection/antiDbg.h"

                                                                                                                                                                                                                                                                        inline std::string სახელი = _xor_(("Injective"));
                                                                                                                                                                                                                                                                        inline std::string მესაკუთრე = _xor_(("xdJ0wOOgAZ"));
                                                                                                                                                                                                                                                                        inline std::string საიდუმლო = _xor_(("797406e0f23efcd693534e7a534b9b453bedb6d169d7928c844391f648c8e8fc"));
																																																																		inline std::string ვერსია = _xor_(("2.0"));
																																																																		inline std::string ბმული = _xor_(("https://keyauth.win/api/1.2/"));
																																																																		inline KeyAuth::api აპლიკაცია(სახელი, მესაკუთრე, საიდუმლო, ვერსია, ბმული);

/////////////////////////////////
BYTE remote_load_library[96] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24, 0x20,
	0x83, 0x38, 0x00, 0x75, 0x3D, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x40,
	0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x83, 0xC0, 0x18, 0x48, 0x8B, 0xC8, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B,
	0x4C, 0x24, 0x20, 0x48, 0x89, 0x41, 0x10, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
};

BYTE remote_call_dll_main[92] =
{
	0x48, 0x83, 0xEC, 0x38, 0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x48, 0x89, 0x44, 0x24, 0x20, 0x48, 0x8B, 0x44, 0x24,
	0x20, 0x83, 0x38, 0x00, 0x75, 0x39, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48,
	0x8B, 0x40, 0x08, 0x48, 0x89, 0x44, 0x24, 0x28, 0x45, 0x33, 0xC0, 0xBA, 0x01, 0x00, 0x00, 0x00, 0x48, 0x8B, 0x44, 0x24, 0x20, 0x48, 0x8B,
	0x48, 0x10, 0xFF, 0x54, 0x24, 0x28, 0x48, 0x8B, 0x44, 0x24, 0x20, 0xC7, 0x00, 0x02, 0x00, 0x00, 0x00, 0x48, 0x83, 0xC4, 0x38, 0xC3, 0xCC
}; DWORD shell_data_offset = 0x6;
/////////////////////////////////

/////////////////////////////////
typedef struct _load_library_struct
{
	int status;
	uintptr_t fn_load_library_a;
	uintptr_t module_base;
	char module_name[80];
}load_library_struct;

typedef struct _main_struct
{
	int status;
	uintptr_t fn_dll_main;
	HINSTANCE dll_base;
} main_struct;
/////////////////////////////////

/////////////////////////////////
uintptr_t call_remote_load_library(HANDLE pid, DWORD thread_id, LPCSTR dll_name)
{
	SPOOF_FUNC
		//printf(("[-] Load Error 1\n"));
		/////////////////////////////////
		HMODULE nt_dll = SPOOF_CALL(LoadLibraryW)((L"ntdll.dll"));
	/////////////////////////////////
	//printf(("[-] Load Error 2\n"));
	/////////////////////////////////
	PVOID alloc_shell_code = driver().allocate_process_memory(pid, 4096, PAGE_EXECUTE_READWRITE);
	//printf(("[-] Load Error 3\n"));
	DWORD shell_size = sizeof(remote_load_library) + sizeof(load_library_struct);
	//printf(("[-] Load Error 4\n"));
	PVOID alloc_local = (VirtualAlloc)(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	/////////////////////////////////
	//printf(("[-] Load Error 5\n"));

	/////////////////////////////////
	RtlCopyMemory(alloc_local, &remote_load_library, sizeof(remote_load_library));
	//printf(("[-] Load Error 6\n"));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_load_library);
	//printf(("[-] Load Error 7\n"));
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	//printf(("[-] Load Error 8\n"));
	load_library_struct* ll_data = (load_library_struct*)((uintptr_t)alloc_local + sizeof(remote_load_library));
	//printf(("[-] Load Error 9\n"));
	ll_data->fn_load_library_a = (uintptr_t)LoadLibraryA;
	//printf(("[-] Load Error 10\n"));
	strcpy_s(ll_data->module_name, 80, dll_name);
	/////////////////////////////////
	//printf(("[-] Load Error 11\n"));
	/////////////////////////////////
	driver().write_process_memory(pid, alloc_shell_code, alloc_local, shell_size);
	//printf(("[-] Load Error 12\n"));
	HHOOK h_hook = SetWindowsHookEx(WH_MOUSE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	/////////////////////////////////
	//printf(("[-] Load Error 13\n"));
	/////////////////////////////////
	while (ll_data->status != 2)
	{
		//printf(("[-] Load Error 14\n"));
		//PostThreadMessage(thread_id, WM_NULL, 0, 0);
		//printf(("[-] Load Error 15\n"));
		driver().read_process_memory(pid, (PVOID)shell_data, (PVOID)ll_data, sizeof(load_library_struct));
		//printf(("[-] Load Error 16\n"));
		Sleep(10);
	}
	uintptr_t mod_base = ll_data->module_base;
	/////////////////////////////////
	//printf(("[-] Load Error 17\n"));
	/////////////////////////////////
	SPOOF_CALL(UnhookWindowsHookEx)(h_hook);
	//printf(("[-] Load Error 18\n"));
	driver().free_process_memory(pid, alloc_shell_code);
	//printf(("[-] Load Error 19\n"));
	SPOOF_CALL(VirtualFree)(alloc_local, 0, MEM_RELEASE);
	//printf(("[-] Load Error 20\n"));
	/////////////////////////////////

	return mod_base;
}
/////////////////////////////////

/////////////////////////////////
void call_dll_main(HANDLE process_id, DWORD thread_id, PVOID dll_base, PIMAGE_NT_HEADERS nt_header, bool hide_dll)
{
	SPOOF_FUNC
		/////////////////////////////////
		HMODULE nt_dll = SPOOF_CALL(LoadLibraryW)((L"ntdll.dll"));
	/////////////////////////////////

	/////////////////////////////////
	PVOID alloc_shell_code = driver().allocate_process_memory(process_id, 4096, PAGE_EXECUTE_READWRITE);
	DWORD shell_size = sizeof(remote_call_dll_main) + sizeof(main_struct);
	PVOID alloc_local = (VirtualAlloc)(NULL, shell_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	/////////////////////////////////

	/////////////////////////////////
	RtlCopyMemory(alloc_local, &remote_call_dll_main, sizeof(remote_call_dll_main));
	uintptr_t shell_data = (uintptr_t)alloc_shell_code + sizeof(remote_call_dll_main);
	*(uintptr_t*)((uintptr_t)alloc_local + shell_data_offset) = shell_data;
	main_struct* main_data = (main_struct*)((uintptr_t)alloc_local + sizeof(remote_call_dll_main));
	main_data->dll_base = (HINSTANCE)dll_base;
	main_data->fn_dll_main = ((uintptr_t)dll_base + nt_header->OptionalHeader.AddressOfEntryPoint);
	/////////////////////////////////

	/////////////////////////////////
	driver().write_process_memory(process_id, alloc_shell_code, alloc_local, shell_size);
	HHOOK h_hook = SetWindowsHookEx(WH_MOUSE, (HOOKPROC)alloc_shell_code, nt_dll, thread_id);
	/////////////////////////////////

	/////////////////////////////////
	while (main_data->status != 2)
	{
		//PostThreadMessage(thread_id, WM_NULL, 0, 0);
		driver().read_process_memory(process_id, (PVOID)shell_data, (PVOID)main_data, sizeof(main_struct));
		Sleep(10);
	}
	/////////////////////////////////

	/////////////////////////////////
	SPOOF_CALL(UnhookWindowsHookEx)(h_hook);
	driver().free_process_memory(process_id, alloc_shell_code);
	SPOOF_CALL(VirtualFree)(alloc_local, 0, MEM_RELEASE);
	/////////////////////////////////
}

PVOID rva_va(uintptr_t rva, PIMAGE_NT_HEADERS nt_head, PVOID local_image)
{
	SPOOF_FUNC
		PIMAGE_SECTION_HEADER p_first_sect = IMAGE_FIRST_SECTION(nt_head);
	for (PIMAGE_SECTION_HEADER p_section = p_first_sect; p_section < p_first_sect + nt_head->FileHeader.NumberOfSections; p_section++)
		if (rva >= p_section->VirtualAddress && rva < p_section->VirtualAddress + p_section->Misc.VirtualSize)
			return (PUCHAR)local_image + p_section->PointerToRawData + (rva - p_section->VirtualAddress);

	return NULL;
}

uintptr_t resolve_func_addr(LPCSTR modname, LPCSTR modfunc)
{
	SPOOF_FUNC
		HMODULE h_module = (LoadLibraryExA)(modname, NULL, DONT_RESOLVE_DLL_REFERENCES);
	uintptr_t func_offset = (uintptr_t)GetProcAddress(h_module, modfunc);
	func_offset -= (uintptr_t)h_module;
	SPOOF_CALL(FreeLibrary)(h_module);

	return func_offset;
}

BOOL relocate_image(PVOID p_remote_img, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	SPOOF_FUNC
		struct reloc_entry
	{
		ULONG to_rva;
		ULONG size;
		struct
		{
			WORD offset : 12;
			WORD type : 4;
		} item[1];
	};

	uintptr_t delta_offset = (uintptr_t)p_remote_img - nt_head->OptionalHeader.ImageBase;
	if (!delta_offset) return true; else if (!(nt_head->OptionalHeader.DllCharacteristics & IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE)) return false;
	reloc_entry* reloc_ent = (reloc_entry*)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress, nt_head, p_local_img);
	uintptr_t reloc_end = (uintptr_t)reloc_ent + nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size;

	if (reloc_ent == nullptr)
		return true;

	while ((uintptr_t)reloc_ent < reloc_end && reloc_ent->size)
	{
		DWORD records_count = (reloc_ent->size - 8) >> 1;
		for (DWORD i = 0; i < records_count; i++)
		{
			WORD fix_type = (reloc_ent->item[i].type);
			WORD shift_delta = (reloc_ent->item[i].offset) % 4096;

			if (fix_type == IMAGE_REL_BASED_ABSOLUTE)
				continue;

			if (fix_type == IMAGE_REL_BASED_HIGHLOW || fix_type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t fix_va = (uintptr_t)rva_va(reloc_ent->to_rva, nt_head, p_local_img);

				if (!fix_va)
					fix_va = (uintptr_t)p_local_img;

				*(uintptr_t*)(fix_va + shift_delta) += delta_offset;
			}
		}

		reloc_ent = (reloc_entry*)((LPBYTE)reloc_ent + reloc_ent->size);
	} return true;
}

BOOL resolve_import(HANDLE pid, DWORD thread_id, PVOID p_local_img, PIMAGE_NT_HEADERS nt_head)
{
	SPOOF_FUNC
		PIMAGE_IMPORT_DESCRIPTOR import_desc = (PIMAGE_IMPORT_DESCRIPTOR)rva_va(nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress, nt_head, p_local_img);
	if (!nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress || !nt_head->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size)
		return true;

	LPSTR module_name = NULL;
	while ((module_name = (LPSTR)rva_va(import_desc->Name, nt_head, p_local_img)))
	{
		uintptr_t base_image;
		base_image = call_remote_load_library(pid, thread_id, module_name);

		if (!base_image)
			return false;

		PIMAGE_THUNK_DATA ih_data = (PIMAGE_THUNK_DATA)rva_va(import_desc->FirstThunk, nt_head, p_local_img);
		while (ih_data->u1.AddressOfData)
		{
			if (ih_data->u1.Ordinal & IMAGE_ORDINAL_FLAG)
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)(ih_data->u1.Ordinal & 0xFFFF));
			else
			{
				IMAGE_IMPORT_BY_NAME* ibn = (PIMAGE_IMPORT_BY_NAME)rva_va(ih_data->u1.AddressOfData, nt_head, p_local_img);
				ih_data->u1.Function = base_image + resolve_func_addr(module_name, (LPCSTR)ibn->Name);
			} ih_data++;
		} import_desc++;
	} return true;
}

void write_sections(HANDLE pid, PVOID p_module_base, PVOID local_image, PIMAGE_NT_HEADERS nt_head)
{
	SPOOF_FUNC
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		driver().write_process_memory(pid, (PVOID)((uintptr_t)p_module_base + section->VirtualAddress), (PVOID)((uintptr_t)local_image + section->PointerToRawData), section->SizeOfRawData);
	}
}

void erase_discardable_sect(HANDLE pid, PVOID p_module_base, PIMAGE_NT_HEADERS nt_head)
{
	SPOOF_FUNC
		PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(nt_head);
	for (WORD sec_cnt = 0; sec_cnt < nt_head->FileHeader.NumberOfSections; sec_cnt++, section++)
	{
		if (section->SizeOfRawData == 0)
			continue;

		if (section->Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			PVOID zero_memory = VirtualAlloc(NULL, section->SizeOfRawData, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			driver().write_process_memory(pid, (PVOID)((uintptr_t)p_module_base + section->VirtualAddress), zero_memory, section->SizeOfRawData);
			VirtualFree(zero_memory, 0, MEM_RELEASE);
		}
	}
}
/////////////////////////////////
void ILikepysen(HANDLE process_id, uint64_t addr, uint64_t size, DWORD protect)
{
	SPOOF_FUNC
		driver().protect_memory(process_id, (uint64_t)addr, size, protect);
}

/////////////////////////////////
void pysen(LPCSTR window_class_name, LPCWSTR dll_path)
{
	SPOOF_FUNC
	//აპლიკაცია.check();
	//std::thread(security_loop).detach();

	PIMAGE_NT_HEADERS dll_nt_head = RtlImageNtHeader(rawData);
	if (!dll_nt_head)
	{
		system("cls");
		(printf)(skCrypt("\n \033[0m[\033[1;31m!\033[0m]"));
		std::cout << (skCrypt(" Issue With DLL")) << std::endl;
	}
	//აპლიკაცია.check();

	//std::thread(security_loop).detach();

	DWORD thread_id;
	DWORD process_id = get_process_id_and_thread_id_by_window_class(window_class_name, &thread_id);
	//აპლიკაცია.check();

	system("cls");
	(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
	std::cout << (skCrypt(" Vunerable AntiCheat Packet Found At -> ")) << process_id << std::endl;
	Sleep(800);
	//აპლიკაცია.check();
	std::thread(security_loop).detach();

	(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
	std::cout << (skCrypt(" Second Vunerable AntiCheat Packet Found At -> ")) << thread_id << std::endl;
	Sleep(800);
	//აპლიკაცია.check();
	//std::thread(security_loop).detach();


	if (process_id != 0 && thread_id != 0)
	{
		//აპლიკაცია.check();


		PVOID allocate_base = driver().allocate_process_memory((HANDLE)process_id, dll_nt_head->OptionalHeader.SizeOfImage, PAGE_EXECUTE_READWRITE);
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		std::cout << (skCrypt(" Anticheat Packet Emulated At -> ")) << allocate_base << std::endl;
		auto endAddr = (uint64_t)((uint64_t)allocate_base + dll_nt_head->OptionalHeader.SizeOfImage);
		std::thread(security_loop).detach();

		if (!relocate_image(allocate_base, rawData, dll_nt_head))
		{
			driver().free_process_memory((HANDLE)process_id, allocate_base);
			(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
			std::cout << (skCrypt("Error #1 ->")) << std::endl;
		}

		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		std::cout << (skCrypt(" Relocated Image ")) << std::endl;
		Sleep(800);
		//აპლიკაცია.check();
		std::thread(security_loop).detach();
		if (!resolve_import((HANDLE)process_id, thread_id, rawData, dll_nt_head))
		{
			driver().free_process_memory((HANDLE)process_id, allocate_base);
			std::cout << (skCrypt("Error #2 ")) << std::endl;
		}
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		//აპლიკაცია.check();

		std::cout << (skCrypt(" Resolved imports ")) << std::endl;
		Sleep(800);

		write_sections((HANDLE)process_id, allocate_base, rawData, dll_nt_head);
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		//აპლიკაცია.check();

		std::cout << (skCrypt(" Wrote Sections ")) << std::endl;
		Sleep(800);
		//აპლიკაცია.check();

		call_dll_main((HANDLE)process_id, thread_id, allocate_base, dll_nt_head, false);
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));

		std::cout << (skCrypt(" DllMain was called ")) << std::endl;
		Sleep(800);
		//აპლიკაცია.check();
		std::thread(security_loop).detach();

		erase_discardable_sect((HANDLE)process_id, allocate_base, dll_nt_head);
		VirtualFree(rawData, 0, MEM_RELEASE);
		system("cls");
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		std::cout << (skCrypt(" Done! ")) << std::endl;
		Sleep(800);
		system("cls");
		(printf)(skCrypt("\n \033[0m[\033[1;31m~\033[0m]"));
		std::cout << (skCrypt(" Injection Sucefull ! ")) << std::endl;
		Sleep(1200);
		exit(0);
	}
	else
	{
		//აპლიკაცია.check();
		std::thread(security_loop).detach();

		printf(("process not found!\n"));
	}
}
/////////////////////////////////


