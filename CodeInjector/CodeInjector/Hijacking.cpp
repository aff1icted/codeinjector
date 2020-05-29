#include "Hijacking.h"

using namespace std;

#pragma comment(lib,"ntdll.lib")

extern "C" NTSTATUS NTAPI RtlAdjustPrivilege(ULONG Privilege, BOOLEAN Enable, BOOLEAN CurrentThread, PBOOLEAN Enabled);

#define Se_debug_privilage 20

char shell_code[] =
{
	0x60, 0xE8, 0x00, 0x00, 0x00, 0x00, 0x5B, 0x81, 0xEB, 0x06, 0x00, 0x00,
	0x00, 0xB8, 0xCC, 0xCC, 0xCC, 0xCC, 0x8D, 0x93, 0x22, 0x00, 0x00, 0x00,
	0x52, 0xFF, 0xD0, 0x61, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xC3
};


void Hijacking::injetcion(DWORD proc_id, char dll_path[MAX_PATH])
{
	{
		LPBYTE ptr;
		HANDLE h_process, h_thread, h_snap;
		PVOID allocated_memory, buffer;
		boolean buff;

		THREADENTRY32 te32;
		CONTEXT ctx;

		te32.dwSize = sizeof(te32);
		ctx.ContextFlags = CONTEXT_FULL;

		RtlAdjustPrivilege(Se_debug_privilage, true, false, &buff);

		h_process = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
		if (!h_process)
		{
			error("OpenProcess", "Failed to open a handle to process");
		}

		h_snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, NULL);

		Thread32First(h_snap, &te32);

		while (Thread32Next(h_snap, &te32))
		{
			if (te32.th32OwnerProcessID == proc_id)
			{
				break;
			}
		}

		CloseHandle(h_snap);

		allocated_memory = VirtualAllocEx(h_process, nullptr, 4096, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		if (!allocated_memory)
		{
			CloseHandle(h_process);
			error("VirtualAllocEx", "Failed to allocated memory");
		}

		h_thread = OpenThread(THREAD_ALL_ACCESS, FALSE, te32.th32ThreadID);
		if (!h_thread)
		{
			VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
			CloseHandle(h_process);
			error("OpenThread", "Failed to open handle to the thread");
		}

		SuspendThread(h_thread);
		GetThreadContext(h_thread, &ctx);

		buffer = VirtualAlloc(NULL, 65536, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);

		ptr = (LPBYTE)buffer;
		memcpy(buffer, shell_code, sizeof(shell_code));

		while (1)
		{
			if (*ptr == 0xB8 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
			{
				*(PDWORD)(ptr + 1) = (DWORD)LoadLibraryA;
			}
			if (*ptr == 0x68 && *(PDWORD)(ptr + 1) == 0xCCCCCCCC)
			{
				*(PDWORD)(ptr + 1) = ctx.Eip;
			}

			if (*ptr == 0xC3)
			{
				ptr++;
				break;
			}
			ptr++;
		}

		strcpy((char*)ptr, dll_path);

		if (!WriteProcessMemory(h_process, allocated_memory, buffer, sizeof(shell_code) + strlen((char*)ptr), nullptr))
		{
			VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
			ResumeThread(h_thread);

			CloseHandle(h_thread);
			CloseHandle(h_process);

			VirtualFree(buffer, NULL, MEM_RELEASE);
			error("WriteProcessMemory", "Failed to write process memory");
		}

		ctx.Eip = (DWORD)allocated_memory;

		if (!SetThreadContext(h_thread, &ctx))
		{
			VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
			ResumeThread(h_thread);

			CloseHandle(h_thread);
			CloseHandle(h_process);

			VirtualFree(buffer, NULL, MEM_RELEASE);
			error("SetThreadContext", "Failed to set thread contex");
		}

		ResumeThread(h_thread);

		CloseHandle(h_thread);
		CloseHandle(h_process);

		VirtualFree(buffer, NULL, MEM_RELEASE);

		MessageBox(0, "Successfully Injected!", "Success", 0);

	}
}
