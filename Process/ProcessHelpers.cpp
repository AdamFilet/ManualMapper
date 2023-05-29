#include "ProcessHelpers.hpp"

#include <Windows.h>
#include <TlHelp32.h>
#include <algorithm>

bool ProcessHelpers::IsOpen(const std::string& processName)
{
	return ProcessHelpers::GetProcessID(processName) != 0;
}

uint32_t ProcessHelpers::GetProcessID(const std::string& processName)
{
	HANDLE snapshot = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	if (snapshot == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	PROCESSENTRY32 entry;
	entry.dwSize = sizeof(PROCESSENTRY32);

	if (!::Process32First(snapshot, &entry))
	{
		::CloseHandle(snapshot);
		return false;
	}

	uint32_t pid = 0;
	std::string processNameToLower = std::string(processName.cbegin(), processName.cend());
	std::transform(processNameToLower.begin(), processNameToLower.end(), processNameToLower.begin(), [](char c) -> char { return ::tolower(c); });
	
	do
	{
		std::string currentProcessName = std::string(entry.szExeFile);
		std::transform(currentProcessName.begin(), currentProcessName.end(), currentProcessName.begin(), [](char c) -> char { return ::tolower(c); });
	
		if (processNameToLower.compare(currentProcessName) == 0)
		{
			pid = entry.th32ProcessID;
			break;
		}
	} while (::Process32Next(snapshot, &entry));

	::CloseHandle(snapshot);
	return pid;
}
