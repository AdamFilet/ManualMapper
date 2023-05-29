#include "Process.hpp"
#include "ProcessHelpers.hpp"

#include <algorithm>
#include <TlHelp32.h>

Process::~Process()
{
	if (m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_Handle);
	}
}

bool Process::Attach(const std::string& processName)
{
	m_Pid = ProcessHelpers::GetProcessID(processName);
	if (m_Pid == 0)
	{
		return false;
	}

	m_Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, m_Pid);
	if (m_Handle == nullptr || m_Handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	m_Name = processName;
}

bool Process::Read(void* address, void* value, size_t size)
{
	return ReadProcessMemory(this->m_Handle, address, value, size, nullptr);
}

bool Process::Write(void* address, const void* value, size_t size)
{
	return WriteProcessMemory(this->m_Handle, address, value, size, nullptr);
}

uintptr_t Process::AllocateMemory(uint32_t size, uint32_t allocationType, uint32_t allocationProtect)
{
	return reinterpret_cast<uintptr_t>(VirtualAllocEx(this->m_Handle, 0, size, allocationType, allocationProtect));
}

uintptr_t Process::GetModuleAddress(const std::string& moduleBase)
{
	uintptr_t modBaseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, this->m_PID);
	if (!hSnap)
	{
		return 0;
	}

	MODULEENTRY32 modEntry;
	modEntry.dwSize = sizeof(MODULEENTRY32);

	std::string moduleName = moduleBase;
	std::string moduleNameToLower = std::string(moduleName.cbegin(), moduleName.cend());
	std::transform(moduleNameToLower.begin(), moduleNameToLower.end(), moduleNameToLower.begin(), [](char c) -> char { return ::tolower(c); });

	if (Module32First(hSnap, &modEntry))
	{
		do
		{
			std::string currentModuleNameLower = std::string(modEntry.szModule);
			std::transform(currentModuleNameLower.begin(), currentModuleNameLower.end(), currentModuleNameLower.begin(), [](char c) -> char { return ::tolower(c); });

			if (!moduleName.compare(currentModuleNameLower))
			{
				modBaseAddress = (uintptr_t)modEntry.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnap, &modEntry));
	}
	CloseHandle(hSnap);
	return modBaseAddress;
}
