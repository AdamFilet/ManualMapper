#pragma once

#include <Windows.h>
#include <cstdint>
#include <vector>
#include <string>

class PEHelpers
{
public:
	static bool CopySections(class PE& file, class Process& process, uintptr_t image);
	static bool ResolveRelocations(PE& file, Process& process, uintptr_t image);
	static bool ResolveImports(PE& file, Process& process, uintptr_t image);
	static bool FixProtections(PE& file, Process& process, uintptr_t image);
	static IMAGE_SECTION_HEADER* FindSectionByName(const HMODULE moduleHandle, const std::string& sectionName);

};