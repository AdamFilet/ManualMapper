#include <string>

#include "Mapper.hpp"

int main()
{
	constexpr const char* DLL_PATH = "DLL_PATH";			// Put your DLL Path here
	constexpr const char* PROCESS_NAME = "PROCESS_NAME";	// Put the desired process to manually map into here

	Mapper map;
	map.SelectFile(DLL_PATH);
	map.SelectProcess(PROCESS_NAME);
	map.MapImage();

	return 0;
}