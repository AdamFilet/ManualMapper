#include "PE.hpp"

#include <fstream>
#include <spdlog/spdlog.h>

bool PE::Initialize(const std::string& path)
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

	if (!this->parseImports())
	{
		SPDLOG_ERROR("Failed to parse imports");
		return false;
	}

	return true;
}

uintptr_t PE::ResolveFileOffset(uintptr_t rva)
{
	for (const auto& sectionHeader : m_Sections)
	{
		if (rva >= sectionHeader.VirtualAddress && rva < sectionHeader.VirtualAddress + sectionHeader.Misc.VirtualSize)
		{
			return reinterpret_cast<uintptr_t>(m_Buffer.data()) + sectionHeader.PointerToRawData + (rva - sectionHeader.VirtualAddress);
		}
	}

	return 0;
}

bool PE::parseImports()
{
	auto& importData = this->m_NtHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
	if (importData.Size == 0)
	{
		return true;
	}

	IMAGE_IMPORT_DESCRIPTOR* importDescriptor = this->ResolveFileOffset<IMAGE_IMPORT_DESCRIPTOR>(importData.VirtualAddress);
	if (importDescriptor == nullptr)
	{
		return false;
	}

	for (; importDescriptor->Name; ++importDescriptor)
	{
		uint32_t iatIndex = 0;
		uint32_t thunk = importDescriptor->OriginalFirstThunk ? importDescriptor->OriginalFirstThunk : importDescriptor->FirstThunk;
		uint8_t* rvaPointer = this->ResolveFileOffset<uint8_t>(thunk);
		std::string dllString = this->ResolveFileOffset<char>(importDescriptor->Name);

		IMAGE_THUNK_DATA64* thunkData = reinterpret_cast<IMAGE_THUNK_DATA64*>(rvaPointer);
		while (thunkData->u1.AddressOfData)
		{
			uintptr_t addressOfData = thunkData->u1.AddressOfData;
			IMAGE_IMPORT_BY_NAME* addressTable = this->ResolveFileOffset<IMAGE_IMPORT_BY_NAME>(addressOfData);

			Import currentImport;
			if (addressOfData < IMAGE_ORDINAL_FLAG64 && addressTable->Name[0])
			{
				currentImport.Name = addressTable->Name;
				currentImport.Ordinal = 0;
			}
			else
			{
				currentImport.Ordinal = addressOfData & 0xFFFF;
				currentImport.Name = "None";
			}

			if (importDescriptor->FirstThunk)
			{
				currentImport.Pointer = importDescriptor->FirstThunk + iatIndex;
			}
			else
			{
				currentImport.Pointer = addressOfData - reinterpret_cast<uintptr_t>(this->m_Buffer.data());
			}

			thunkData++;
			iatIndex += sizeof(uint64_t);
			this->m_Imports[dllString].emplace_back(currentImport);
		}
	}

	return true;
}
