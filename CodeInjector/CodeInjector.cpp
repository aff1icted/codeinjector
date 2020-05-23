#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <libloaderapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <io.h>
#include "Hijacking.h"
#include "Inject.h"
using namespace std;


bool fileExist(char* name)
{
	return _access(name, 0) != -1;
}

int main()
{
	char dll_path[MAX_PATH];
	char dll_name[64];
	DWORD proc_id;
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

				cout << "Enter process ID: ";
				cin >> proc_id;
				cout << "Enter dll name: ";
				cin >> dll_name;
				GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr);
				if (fileExist(dll_path) == 0)
				{
					cout << "dll not found" << endl;;
					break;
				}
				inj1.injetcion(proc_id, dll_path);
				break;
			case '2':
				cout << "Enter process ID: ";
				cin >> proc_id;
				cout << "Enter dll name: ";
				cin >> dll_name;
				GetFullPathName(dll_name, MAX_PATH, dll_path, nullptr);
				if (fileExist(dll_path) == 0)
				{
					cout << "dll not found" << endl;;
					break;
				}
				inj2.injetcion(proc_id, dll_path);
				break;
			case '0':
				break;
			default:
				cout << "Incorrect input" << endl;
				break;
		}
	
	
	}
	
}