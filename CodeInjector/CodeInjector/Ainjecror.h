#pragma once
#include <iostream>
#include <windows.h>
#include <string>
#include <thread>
#include <libloaderapi.h>
#include <TlHelp32.h>
#include <stdio.h>
#include <io.h>


class Ainjector
{
public:
	virtual void injetcion(DWORD proc_id, char dll_path[MAX_PATH]) = 0;


protected:

	void error(const char* error_title, const char* error_massage);
	

private:

};
