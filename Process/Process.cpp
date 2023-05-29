#include "Process.hpp"
#include "ProcessHelpers.hpp"

#include <vector>
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

bool Process::Protect(uintptr_t address, uint32_t size, uint32_t protection, uint32_t& oldProtection)
{
	return VirtualProtectEx(this->m_Handle, reinterpret_cast<LPVOID>(address), size, protection, reinterpret_cast<PDWORD>(&oldProtection));
}

uintptr_t Process::GetModuleAddress(const std::string& moduleBase)
{
	uintptr_t modBaseAddress = 0;
	HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, m_Pid);
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

			if (!moduleNameToLower.compare(currentModuleNameLower))
			{
				modBaseAddress = (uintptr_t)modEntry.modBaseAddr;
				break;
			}
		} while (Module32Next(hSnap, &modEntry));
	}
	CloseHandle(hSnap);
	return modBaseAddress;
}

uintptr_t Process::GetProcAddress(uintptr_t remoteModuleBase, const std::string& ordinalName)
{
	if (remoteModuleBase == 0)
	{
		return {};
	}

	IMAGE_DOS_HEADER dosHeader;
	if (!this->Read(remoteModuleBase, dosHeader))
	{
		return {};
	}

	IMAGE_NT_HEADERS ntHeader;
	if (!this->Read(dosHeader.e_lfanew + remoteModuleBase, ntHeader))
	{
		return {};
	}

	uintptr_t exportBase = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
	if (exportBase == 0)
	{
		return {};
	}

	uint32_t exportSize = ntHeader.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;
	std::vector<uint8_t> exportInfo(exportSize);
	if (!this->Read(reinterpret_cast<void*>(remoteModuleBase + exportBase), exportInfo.data(), exportSize))
	{
		return {};
	}

	IMAGE_EXPORT_DIRECTORY* exportData = reinterpret_cast<IMAGE_EXPORT_DIRECTORY*>(exportInfo.data());
	uint16_t* addressOfOrds = reinterpret_cast<uint16_t*>(exportData->AddressOfNameOrdinals + reinterpret_cast<uintptr_t>(exportInfo.data()) - exportBase);
	uint32_t* addressOfNames = reinterpret_cast<uint32_t*>(exportData->AddressOfNames + reinterpret_cast<uintptr_t>(exportInfo.data()) - exportBase);
	uint32_t* addressOfFuncs = reinterpret_cast<uint32_t*>(exportData->AddressOfFunctions + reinterpret_cast<uintptr_t>(exportInfo.data()) - exportBase);

	uintptr_t procAddress = 0;

	for (uint32_t i = 0; i < exportData->NumberOfFunctions; ++i)
	{
		uint16_t ordinalIndex = 0xFFFF;
		char* name = nullptr;
		if (reinterpret_cast<uintptr_t>(ordinalName.c_str()) <= 0xFFFF)
		{
			ordinalIndex = static_cast<WORD>(i);
		}
		else if (reinterpret_cast<uintptr_t>(ordinalName.c_str()) > 0xFFFF && i < exportData->NumberOfNames)
		{
			name = (char*)(addressOfNames[i] + reinterpret_cast<uintptr_t>(exportInfo.data()) - exportBase);
			ordinalIndex = static_cast<WORD>(addressOfOrds[i]);
		}
		else
		{
			return 0;
		}

		if (reinterpret_cast<uintptr_t>(ordinalName.c_str()) <= 0xFFFF && static_cast<uint16_t>(reinterpret_cast<uintptr_t>(ordinalName.c_str()) == (ordinalIndex + exportData->Base)) || (reinterpret_cast<uintptr_t>(ordinalName.c_str()) > 0xFFFF && ordinalName.compare(name) == 0))
		{
			procAddress = addressOfFuncs[ordinalIndex] + remoteModuleBase;
			break;
		}
	}

	return procAddress;
}
