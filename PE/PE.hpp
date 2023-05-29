#pragma once

#include <Windows.h>
#include <string>
#include <vector>

class PE
{
public:
	bool Initialize(const std::string& path);

public:
	uint32_t m_ImageSize;
	IMAGE_NT_HEADERS* m_NtHeaders;
	std::vector<IMAGE_SECTION_HEADER> m_Sections;

public:
	std::vector<uint8_t> m_Buffer;

};