#pragma once
#include "Ainjecror.h"



class Hijacking : public Ainjector
{
public:
	void injetcion(DWORD proc_id, char dll_path[MAX_PATH]) override;

private:

};