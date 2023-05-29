#include "SchemaResolver.hpp"

#include <algorithm>
#include <codecvt>

std::string SchemaResolver::ResolveApiSetLibrary(const std::string apisetLibrary)
{
	auto iter = std::find_if(this->m_APIMap.begin(), this->m_APIMap.end(), [&apisetLibrary](const auto& val) {
		return apisetLibrary.find(val.first.c_str()) != apisetLibrary.npos;
		});

	if (iter == this->m_APIMap.end())
	{
		return {};
	}

	return iter->second;
}

void SchemaResolver::initialize()
{
	static std::wstring_convert<std::codecvt_utf8<wchar_t>> utf8_conv;

	PEB* peb = reinterpret_cast<PEB*>(reinterpret_cast<TEB*>(NtCurrentTeb())->ProcessEnvironmentBlock);
	PAPI_SET_NAMESPACE_ARRAY setMap = reinterpret_cast<PAPI_SET_NAMESPACE_ARRAY>(peb->ApiSetMap);

	for (uint32_t i = 0; i < setMap->Count; i++)
	{
		wchar_t dllName[MAX_PATH] = { 0 };
		PAPI_SET_NAMESPACE_ENTRY descriptor = setMap->entry(i);
		ULONG nameSize = setMap->apiName(descriptor, dllName);

		std::transform(dllName, dllName + nameSize / sizeof(char), dllName, ::towlower);
		std::wstring dllWString(dllName);

		std::string hostString;
		PAPI_SET_VALUE_ARRAY hostData = setMap->valArray(descriptor);

		PAPI_SET_VALUE_ENTRY host = hostData->entry(setMap, 0);
		std::wstring hostName(reinterpret_cast<wchar_t*>(reinterpret_cast<uint8_t*>(setMap) + host->ValueOffset), host->ValueLength / sizeof(wchar_t));
		hostString = utf8_conv.to_bytes(hostName);

		this->m_APIMap.emplace(utf8_conv.to_bytes(dllWString), std::move(hostString));
	}

	this->m_Initialized = true;
}