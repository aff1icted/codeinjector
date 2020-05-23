#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <libloaderapi.h>
#include <TlHelp32.h>
#include <stdio.h>

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

class Ainjector
{
public:
	virtual void injetcion() = 0;

	
protected:

	void get_proc_id(DWORD &process_id)
	{
		cout << "Enter process ID ";
		cin >> process_id;
	}

	void error(const char* error_title, const char* error_massage)
	{
		MessageBox(0, error_massage, error_title, 0);
		exit(-1);
	}

	bool file_exists(string file_name)
	{
		struct stat buffer;
		return (stat(file_name.c_str(), &buffer) == 0);
	}

private:

};



class Hijacking : public Ainjector
{
public:
	

	void injetcion() override 
	{
		LPBYTE ptr;
		HANDLE h_process, h_thread, h_snap;
		PVOID allocated_memory, buffer;
		DWORD proc_id = NULL;
		boolean buff;

		THREADENTRY32 te32;
		CONTEXT ctx;
		char dll_path[MAX_PATH];
		const char* dll_name = "Test.dll";

		te32.dwSize = sizeof(te32);
		ctx.ContextFlags = CONTEXT_FULL;

		RtlAdjustPrivilege(Se_debug_privilage, true, false, &buff);

		if (!file_exists(dll_name))
		{
			error("file_exists", "File doesn't exist");
		}

		if (!GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr))
		{
			error("GetFullPathName", "failed to get full path");
		}

		get_proc_id(proc_id);
		if (proc_id == NULL)
		{
			error("Get_proc_id", "failed to get process ID");
		}

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

private:	

};


class Inject : public Ainjector
{
public:

	void injetcion() override
	{
		DWORD proc_id = NULL;
		char dll_path[MAX_PATH];
		const char* dll_name = "Test.dll";

		if (!file_exists(dll_name))
		{
			error("file_exists", "File doesn't exist");
		}

		if (!GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr))
		{
			error("GetFullPathName", "failed to get full path");
		}

		get_proc_id(proc_id);
		if (proc_id == NULL)
		{
			error("Get_proc_id", "failed to get process ID");
		}

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

private:

};

int main()
{
	Inject inj1;
	Hijacking inj2;
	char menu = 'a';
	while(menu != '0')
	{
		cout << "Enter:" << endl << "1.Injection" << endl << "2.Thread hijacking" << endl << "0.Exit" << endl;
		cin >> menu;
		
		switch (menu)
		{
			case '1':
				inj1.injetcion();
				break;
			case '2':
				inj2.injetcion();
				break;
			case '0':
				break;
			default:
				cout << "Incorrect input" << endl;
				break;
		}
	
	
	}
	
}