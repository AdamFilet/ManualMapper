#include <string>

#include "PE/PE.hpp"

#define DLLPATH "C:\\Users\\Adam\\source\\repos\\ManualMapper\\Test\\TestDLL.dll"

int main()
{
	PE file;
	file.Initalize(DLLPATH);

	return 0;
}