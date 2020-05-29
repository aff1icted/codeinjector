#include "Inject.h"

void Inject::injetcion(DWORD proc_id, char dll_path[MAX_PATH])
{
	HANDLE h_process = OpenProcess(PROCESS_ALL_ACCESS, NULL, proc_id);
	if (!h_process)
	{
		error("OpenProcess", "Failed to open a handle to process");
	}

	void* allocated_memory = VirtualAllocEx(h_process, nullptr, MAX_PATH, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (!allocated_memory)
	{
		error("VirtualAllocEx", "Failed to allocated memory");
	}

	if (!WriteProcessMemory(h_process, allocated_memory, dll_path, MAX_PATH, nullptr))
	{
		error("WriteProcessMemory", "Failed to write process memory");
	}

	HANDLE h_thread = CreateRemoteThread(h_process, nullptr, NULL, LPTHREAD_START_ROUTINE(LoadLibraryA), allocated_memory, NULL, nullptr);
	if (!h_thread)
	{
		error("CreateRemoteThread", "Failed to create remote thread");
	}

	CloseHandle(h_process);
	VirtualFreeEx(h_process, allocated_memory, NULL, MEM_RELEASE);
	MessageBox(0, "Successfully Injected!", "Success", 0);
}
