#include "PE.hpp"

#include <fstream>
#include <spdlog/spdlog.h>

bool PE::Initalize(const std::string& path)
{
	std::ifstream file(path, std::ios::binary);
	if (!file.is_open())
	{
		SPDLOG_ERROR("Failed to open {}", path);
		return false;
	}

	file.seekg(0, file.end);
	this->m_Buffer.resize(file.tellg());
	file.seekg(0, file.beg);

	if (this->m_Buffer.size() == 0)
	{
		SPDLOG_ERROR("Failed to get file size");
		return false;
	}

	file.read(reinterpret_cast<char*>(this->m_Buffer.data()), this->m_Buffer.size());
	IMAGE_DOS_HEADER* imageDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(this->m_Buffer.data());
	if (imageDosHeader == nullptr)
	{
		SPDLOG_ERROR("Failed get ImageDosHeader");
		return false;
	}

	this->m_NtHeaders = reinterpret_cast<IMAGE_NT_HEADERS*>(this->m_Buffer.data() + imageDosHeader->e_lfanew);
	if (this->m_NtHeaders == nullptr)
	{
		SPDLOG_ERROR("Failed get NTHeader");

		return false;
	}

	this->m_ImageSize = this->m_NtHeaders->OptionalHeader.SizeOfImage;
	const IMAGE_SECTION_HEADER* sectionHeader = IMAGE_FIRST_SECTION(this->m_NtHeaders);
	for (uint16_t i = 0; i <= this->m_NtHeaders->FileHeader.NumberOfSections; ++i, ++sectionHeader)
	{
		this->m_Sections.emplace_back(*sectionHeader);
	}

	return true;
}
