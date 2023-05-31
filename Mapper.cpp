#include "Mapper.hpp"

#include "PE/PE.hpp"
#include "PE/PEHelpers.hpp"

#include "Process/Process.hpp"

#include <spdlog/spdlog.h>

#define QWORD_TO_BYTES(bytes) bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7]

bool Mapper::SelectProcess(const std::string& targetProcess)
{
	if (!this->m_Process.Attach(targetProcess))
	{
		return false;
	}

	return true;
}

bool Mapper::SelectFile(const std::string& filePath)
{
	if (!this->m_File.Initialize(filePath))
	{
		return false;
	}

	return true;
}

bool Mapper::MapImage()
{
	uintptr_t imageSize = this->m_File.m_NtHeaders->OptionalHeader.SizeOfImage;
	uintptr_t mappedImage = this->m_Process.AllocateMemory(imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	if (mappedImage == 0)
	{
		SPDLOG_ERROR("Failed to allocate memory");
		return false;
	}

	if (!PEHelpers::CopySections(m_File, m_Process, mappedImage))
	{
		SPDLOG_ERROR("Failed to copy sections");
		return false;
	}

	if (!PEHelpers::ResolveRelocations(m_File, m_Process, mappedImage))
	{
		SPDLOG_ERROR("Failed to resolve relocations");
		return false;
	}

	if (!PEHelpers::ResolveImports(m_File, m_Process, mappedImage))
	{
		SPDLOG_ERROR("Failed to resolve imports");
		return false;
	}

	if (!PEHelpers::FixProtections(m_File, m_Process, mappedImage))
	{
		SPDLOG_ERROR("Failed to fix protections");
		return false;
	}

	if (!this->executeMain(mappedImage + 0x1000))
	{
		SPDLOG_ERROR("Failed to execute DLL");
		return false;
	}

	return true;
}

bool Mapper::executeMain(uint64_t entry)
{
	constexpr const char* USER32_NAME = "user32.dll";
	constexpr const char* WIN32U_DLL = "win32u.dll";
	constexpr const char* WIN32U_IMPORT = "NtUserGetMessage";

	HMODULE user32Module = LoadLibraryA(USER32_NAME);
	if (user32Module == nullptr)
	{
		return false;
	}

	IMAGE_SECTION_HEADER* user32Text = PEHelpers::FindSectionByName(user32Module, ".text");
	if (user32Text == nullptr)
	{
		return false;
	}
	
	uintptr_t user32End = reinterpret_cast<uintptr_t>(user32Module) + user32Text->VirtualAddress + user32Text->Misc.VirtualSize;

	char systemPath[255] = { 0 };
	GetSystemDirectoryA(systemPath, 255);

	std::string fullPath = std::string(systemPath) + "\\" + USER32_NAME;
	PE userPE;
	userPE.Initialize(fullPath);

	std::vector<PE::Import>& ntdllImports = userPE.m_Imports[WIN32U_DLL];
	PE::Import importToHijack;

	for (const auto& current : ntdllImports)
	{
		if (current.Name.compare(WIN32U_IMPORT) != 0)
		{
			continue;
		}

		importToHijack = current;
	}

	uintptr_t firstThunk = reinterpret_cast<uintptr_t>(user32Module) + importToHijack.Pointer;
	uintptr_t function = 0;

	if (!m_Process.Read(firstThunk, function))
	{
		return false;
	}
	
	std::vector<uint8_t> firstThunkQword = this->QWORDToBytes(firstThunk);
	std::vector<uint8_t> functionQword = this->QWORDToBytes(function);
	std::vector<uint8_t> entryQword = this->QWORDToBytes(entry);

	std::vector<uint8_t> shellCode =
	{
		0x48, 0xB8, QWORD_TO_BYTES(firstThunkQword),	// mov rax, firstThunk
		0x48, 0xBA, QWORD_TO_BYTES(functionQword),		// mov rdx, function
		0x48, 0x89, 0x10,								// mov [rax], rdx
		0xBA, 0x1, 0, 0, 0,								// mov edx, 1 (DLL_PROCESS_ATTACH)
		0xFF, 0x25, 0, 0, 0, 0,							// jump entry
		QWORD_TO_BYTES(entryQword)
	};
	
	if (!m_Process.Write(reinterpret_cast<void*>(user32End), shellCode.data(), shellCode.size()))
	{
		return false;
	}
	
	uint32_t oldProtection = 0;
	if (!m_Process.Protect(firstThunk, sizeof(uintptr_t), PAGE_READWRITE, oldProtection))
	{
		return false;
	}

	if (!m_Process.Write(firstThunk, user32End))
	{
		return false;
	}

	Sleep(2000);

	if (!m_Process.Protect(firstThunk, sizeof(uintptr_t), oldProtection, oldProtection))
	{
		return false;
	}

	return true;
}

std::vector<uint8_t> Mapper::QWORDToBytes(uint64_t qword)
{
	std::vector<uint8_t> bytes(8);
	for (int i = 0; i < 8; i++) 
	{
		bytes[i] = (qword >> (i * 8)) & 0xFF;
	}

	return bytes;
}