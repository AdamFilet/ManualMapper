#pragma once

#include <vector>
#include <cstdint>

class PEHelpers
{
public:
	static bool CopySections(class PE& file, class Process& process, uintptr_t image);
	static bool ResolveRelocations(PE& file, Process& process, uintptr_t image);
	static bool ResolveImports(PE& file, Process& process, uintptr_t image);
	static bool FixProtections(PE& file, Process& process, uintptr_t image);

};