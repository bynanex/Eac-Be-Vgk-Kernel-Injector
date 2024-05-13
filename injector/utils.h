#pragma once
#include <Windows.h>
#include "definitions.h"
#pragma once
#include "bytes.h"
#include "spoof.h"
using namespace std;
//////////////////////////////////////////////////////////////////////////////////////////////////////////////
PVOID get_dll_by_file(LPCWSTR file_path)
{
	SPOOF_FUNC
	/*HANDLE h_dll = CreateFileW(file_path, GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	if (h_dll == INVALID_HANDLE_VALUE)
		return NULL;*/

	DWORD dll_file_sz = GetFileSize(rawData, NULL);
	PVOID dll_buffer = VirtualAlloc(NULL, dll_file_sz, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

	if (!ReadFile(rawData, dll_buffer, dll_file_sz, NULL, FALSE) || *(PDWORD)dll_buffer != 9460301)
	{
		VirtualFree(dll_buffer, 0, MEM_RELEASE);
		goto exit;
	}

exit:
	CloseHandle(rawData);
	return dll_buffer;
}

std::wstring to_fast_convert_wchar(PCCH a)
{
	SPOOF_FUNC
	std::wstring out_str;

	for (int i = 0; i < strlen(a) + 1; i++)
		out_str.push_back((const wchar_t)a[i]);

	return out_str;
}

DWORD get_process_id_and_thread_id_by_window_class(LPCSTR window_class_name, PDWORD p_thread_id)
{
	SPOOF_FUNC
	DWORD process_id = 0;
	while (!process_id)
	{
		*p_thread_id = GetWindowThreadProcessId(FindWindowA(window_class_name, NULL), &process_id); Sleep(20);
	} return process_id;
}
//////////////////////////////////////////////////////////////////////////////////////////////////////////////



