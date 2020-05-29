#include "Ainjecror.h"

void Ainjector::error(const char * error_title, const char * error_massage)
{
	
	MessageBox(0, error_massage, error_title, 0);
	exit(-1);
	
}
