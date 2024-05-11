#pragma once
#include <Windows.h>
#include <iostream>
#include "spoof.h"
#include "skcrypt.h"
enum INSTRUCTIONS
{
    WRITE_KERNEL_MEMORY,
    WRITE_PROCESS_MEMORY,
    READ_KERNEL_MEMORY,
    READ_PROCESS_MEMORY,
    ALLOCATE_MEMORY,
    FREE_MEMORY,
    PROTECT_MEMORY,
    ATTACH_PROCESS,
    OPEN_PROCESS,
    READ_PROCESS_MEMORY64,
    WRITE_PROCESS_MEMORY64
};
typedef struct _NULL_MEMORY
{
    ULONG instruction;
    void* buffer_address;
    UINT_PTR address;
    ULONGLONG size;
    ULONG pid;
    BOOLEAN read;
    BOOLEAN req_base;
    void* output;
    const char* module_name;
    PVOID allocate_base;//����õ��ĵ�ַ
    DWORD protect;
    PVOID64 address64;
    PVOID64 buffer_address64;
}NULL_MEMORY, * PNULL_MEMORY;



class my_driver
{
public:
    my_driver() {};

    ~my_driver() {};
    static  my_driver& singleton()
    {
        SPOOF_FUNC
        //����ģʽ
        static my_driver p_object;
        return p_object;
    }
    BOOL send_instruction(PNULL_MEMORY pParam)
    {
        SPOOF_FUNC
        //������ͨ��
        void* hooked_function = GetProcAddress(LoadLibrary(E("win32u.dll")), E("NtTokenManagerConfirmOutstandingAnalogToken"));
        if (hooked_function == NULL)
        {
            std::cout << E("[-] driver::send_instruction get NtQueryCompositionSurfaceStatistics failed")  << std::endl;
            return FALSE;
        }
        auto func = static_cast<uint64_t(_stdcall*)(PNULL_MEMORY)>(hooked_function);
        func(pParam);
        return TRUE;
    }
    BOOL read_process_memory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = READ_PROCESS_MEMORY;
        msg.pid = (ULONG)pid;
        msg.address = (UINT_PTR)address;
        msg.buffer_address = buffer;
        msg.size = size;
        return send_instruction(&msg);

    }
    BOOL read_process_memory64(HANDLE pid, PVOID64 address64, PVOID64 buffer64, DWORD size)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = READ_PROCESS_MEMORY64;
        msg.pid = (ULONG)pid;
        msg.address64 = address64;
        msg.buffer_address64 = buffer64;
        msg.size = size;
        return send_instruction(&msg);

    }
    BOOL write_process_memory(HANDLE pid, PVOID address, PVOID buffer, DWORD size)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = WRITE_PROCESS_MEMORY;
        msg.pid = (ULONG)pid;
        msg.address = (UINT_PTR)address;
        msg.buffer_address = buffer;
        msg.size = size;
        return send_instruction(&msg);
    }


    BOOL write_process_memory64(HANDLE pid, PVOID64 address64, PVOID64 buffer64, DWORD size)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = WRITE_PROCESS_MEMORY64;
        msg.pid = (ULONG)pid;
        msg.address64= address64;
        msg.buffer_address64 = buffer64;
        msg.size = size;
        return send_instruction(&msg);
    }
    PVOID allocate_process_memory(HANDLE pid, ULONGLONG size, DWORD protect)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = ALLOCATE_MEMORY;
        msg.pid = (ULONG)pid;
        msg.address = NULL;
        msg.buffer_address = NULL;
        msg.size = size;
        msg.protect = protect;
        send_instruction(&msg);
        return msg.allocate_base;
    }
    BOOL free_process_memory(HANDLE pid, PVOID base)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = FREE_MEMORY;
        msg.pid = (ULONG)pid;
        msg.address = (UINT_PTR)base;
        msg.buffer_address = NULL;
        return send_instruction(&msg);
    }
    BOOL protect_memory(HANDLE pid, UINT_PTR base, ULONGLONG size, DWORD protection)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = PROTECT_MEMORY;
        msg.pid = (ULONG)pid;
        msg.address = (UINT_PTR)base;
        msg.buffer_address = NULL;
        msg.size = size;
        msg.protect = protection;
        return send_instruction(&msg);
    }
    PVOID open_process(HANDLE pid)
    {
        SPOOF_FUNC
        NULL_MEMORY msg;
        msg.instruction = OPEN_PROCESS;
        msg.pid = (ULONG)pid;
        msg.address = NULL;
        msg.buffer_address = NULL;
        msg.size = 0;
        msg.protect = NULL;
        printf(E("open process\n"));
        send_instruction(&msg);
        return msg.buffer_address;
    }
private:
    my_driver(const my_driver&) = delete; 
    my_driver& operator = (const my_driver&) = delete;
};

my_driver& driver()
{
    SPOOF_FUNC
    return my_driver::singleton();
}
