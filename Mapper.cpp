#include "Mapper.hpp"

#include "Process/Process.hpp"
#include "PE/PE.hpp"

#include <spdlog/spdlog.h>

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
	uint64_t imageSize = this->m_File.m_NtHeaders->OptionalHeader.SizeOfImage;
	uintptr_t mappedImage = this->m_Process.AllocateMemory(imageSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	if (mappedImage == 0)
	{
		SPDLOG_ERROR("Failed to allocate memory");

		return false;
	}



	return true;
}