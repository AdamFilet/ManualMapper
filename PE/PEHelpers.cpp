#include "PEHelpers.hpp"

#include "PE.hpp"
#include "../SchemaResolver.hpp"
#include "../Process/Process.hpp"

#include <spdlog/spdlog.h>

bool PEHelpers::CopySections(PE& file, Process& process, uint64_t image)
{
	const IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(file.m_NtHeaders);
	for (const auto& sectionHeader : file.m_Sections)
	{
		if (sectionHeader.SizeOfRawData == 0)
		{
			continue;
		}

		if (sectionHeader.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			continue;
		}

		uintptr_t sectionAddress = image + sectionHeader.VirtualAddress;
		uintptr_t rawDataAddress = reinterpret_cast<uintptr_t>(file.m_Buffer.data()) + sectionHeader.PointerToRawData;
		if (!process.Write(reinterpret_cast<void*>(sectionAddress), reinterpret_cast<void*>(rawDataAddress), sectionHeader.SizeOfRawData))
		{
			SPDLOG_ERROR("Failed to write section {}", reinterpret_cast<const char*>(sectionHeader.Name));

			return false;
		}
	}

	return true;
}

bool PEHelpers::ResolveRelocations(PE& file, Process& process, uintptr_t image)
{
	struct RELOCDATA
	{
		WORD Offset : 12;
		WORD Type : 4;
	};

	IMAGE_NT_HEADERS* ntHeader = file.m_NtHeaders;
	if (ntHeader->FileHeader.Characteristics & IMAGE_FILE_RELOCS_STRIPPED)
	{
		return true;
	}

	auto& baseRelocData = ntHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
	if (baseRelocData.Size == 0)
	{
		return true;
	}

	uintptr_t delta = image - ntHeader->OptionalHeader.ImageBase;
	if (delta == 0)
	{
		return true;
	}

	IMAGE_BASE_RELOCATION* relocationDesc = file.ResolveFileOffset<IMAGE_BASE_RELOCATION>(baseRelocData.VirtualAddress);
	while (relocationDesc->VirtualAddress != NULL && relocationDesc->SizeOfBlock != 0)
	{
		for (uint32_t i = 0; i < relocationDesc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION*) / sizeof(uint16_t); ++i)
		{
			const RELOCDATA relocationData = *reinterpret_cast<const RELOCDATA*>(reinterpret_cast<const uint8_t*>(relocationDesc) + sizeof(IMAGE_BASE_RELOCATION) + i * sizeof(WORD));
			if (relocationData.Offset == 0 && relocationData.Type == 0)
			{
				continue;
			}

			if (relocationData.Type == IMAGE_REL_BASED_DIR64)
			{
				uintptr_t relocationAddress = image + relocationDesc->VirtualAddress + relocationData.Offset;
				uintptr_t buffer = 0;
				if (!process.Read(relocationAddress, buffer))
				{
					return false;
				}

				buffer += delta;

				if (!process.Write(relocationAddress, buffer))
				{
					return false;
				}
			}
		}

		relocationDesc = relocationDesc + relocationDesc->SizeOfBlock;
	}

	return true;
}

bool PEHelpers::ResolveImports(PE& file, Process& process, uintptr_t image)
{
	auto& importDescriptorData = file.m_NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importDescriptorData.Size == 0)
	{
		return true;
	}

	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = file.ResolveFileOffset<IMAGE_IMPORT_DESCRIPTOR>(importDescriptorData.VirtualAddress);
	if (importDescriptor == nullptr)
	{
		return false;
	}

	std::unordered_map<std::string, std::vector<PE::Import>>& imports = file.m_Imports;
	for (const auto& currentImport : imports)
	{
		std::string currentModule = currentImport.first;
		if (currentModule.find("ext-ms") == 0 || currentModule.find("api-ms") == 0)
		{
			currentModule = SchemaResolver::Get()->ResolveApiSetLibrary(currentModule);
		}

		uintptr_t moduleBase = process.GetModuleAddress(currentModule);
		if (moduleBase == 0)
		{
			SPDLOG_ERROR("{} is not loaded", currentModule);
			continue;
		}

		for (const auto& importData : currentImport.second)
		{
			uint64_t procAddress = 0;
			if (importData.Ordinal != 0)
			{
				procAddress = process.GetProcAddress(moduleBase, reinterpret_cast<const char*>(importData.Ordinal));
			}
			else
			{
				procAddress = process.GetProcAddress(moduleBase, importData.Name);
			}

			uintptr_t address = image + importData.Pointer;
			if (!process.Write(address, procAddress))
			{
				return false;
			}
		}
	}

	return true;
}

bool PEHelpers::FixProtections(PE& file, Process& process, uintptr_t image)
{
	const IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(file.m_NtHeaders);
	for (const auto& sectionHeader : file.m_Sections)
	{
		if (sectionHeader.SizeOfRawData == 0)
		{
			continue;
		}

		if (sectionHeader.Characteristics & IMAGE_SCN_MEM_DISCARDABLE)
		{
			continue;
		}

		uintptr_t sectionAddress = image + sectionHeader.VirtualAddress;
		DWORD protection = PAGE_NOACCESS;

		if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE && sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE && sectionHeader.Characteristics & IMAGE_SCN_MEM_READ)
		{
			protection = PAGE_EXECUTE_READWRITE;
		}
		else if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE && sectionHeader.Characteristics & IMAGE_SCN_MEM_READ)
		{
			protection = PAGE_EXECUTE_READ;
		}
		else if (sectionHeader.Characteristics & IMAGE_SCN_MEM_WRITE && sectionHeader.Characteristics & IMAGE_SCN_MEM_READ)
		{
			protection = PAGE_READWRITE;
		}
		else if (sectionHeader.Characteristics & IMAGE_SCN_MEM_EXECUTE)
		{
			protection = PAGE_EXECUTE;
		}
		else if (sectionHeader.Characteristics & IMAGE_SCN_MEM_READ)
		{
			protection = PAGE_READONLY;
		}

		uint32_t oldProtection;
		if (!process.Protect(sectionAddress, sectionHeader.SizeOfRawData, protection, oldProtection))
		{
			SPDLOG_INFO("Failed to set protection for page at {}", sectionAddress);

			return false;
		}
	}
}

IMAGE_SECTION_HEADER* PEHelpers::FindSectionByName(const HMODULE moduleHandle, const std::string& sectionName)
{
	if (moduleHandle == nullptr)
	{
		return nullptr;
	}

	IMAGE_DOS_HEADER* dosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(moduleHandle);
	IMAGE_NT_HEADERS* ntHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(reinterpret_cast<uintptr_t>(moduleHandle) + dosHeader->e_lfanew);
	IMAGE_FILE_HEADER* fileHeader = &ntHeader->FileHeader;

	std::string name = sectionName;
	std::string sectionNameLower = std::string(name.cbegin(), name.cend());
	std::transform(name.begin(), name.end(), name.begin(), [](char c) -> char { return ::tolower(c); });

	IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(ntHeader);
	for (uint32_t i = 0; i < fileHeader->NumberOfSections; ++i, ++sectionHeader)
	{
		std::string currentNameLower = reinterpret_cast<const char*>(sectionHeader->Name);
		std::transform(currentNameLower.begin(), currentNameLower.end(), currentNameLower.begin(), [](char c) -> char { return ::tolower(c); });
		if (sectionNameLower.compare(currentNameLower) == 0)
		{
			return sectionHeader;
		}
	}

	return nullptr;
}
