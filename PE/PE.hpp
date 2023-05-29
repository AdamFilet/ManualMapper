#pragma once

#include <unordered_map>
#include <Windows.h>
#include <string>
#include <vector>

class PE
{
public:
	struct Import
	{
		uint16_t Ordinal;
		std::string Name;
		uintptr_t Pointer;
	};

public:
	bool Initialize(const std::string& path);

public:
	template<typename T>
	T* ResolveFileOffset(uintptr_t rva)
	{
		return reinterpret_cast<T*>(this->ResolveFileOffset(rva));
	}

	uintptr_t ResolveFileOffset(uintptr_t rva);

private:
	bool parseImports();

public:
	uint32_t m_ImageSize;
	IMAGE_NT_HEADERS* m_NtHeaders;
	std::vector<IMAGE_SECTION_HEADER> m_Sections;
	std::unordered_map<std::string, std::vector<Import>> m_Imports;

public:
	std::vector<uint8_t> m_Buffer;

};