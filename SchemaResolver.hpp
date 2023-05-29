#pragma once
#include <string>
#include <vector>
#include <map>

#include "Native.hpp"

class SchemaResolver
{
public:
	std::string ResolveApiSetLibrary(const std::string apisetLibrary);

public:
	static SchemaResolver* Get()
	{
		static SchemaResolver resolver;
		if (!resolver.m_Initialized)
		{
			resolver.initialize();
		}
		return &resolver;
	}

public:
	void initialize();

public:
	std::map<std::string, std::string> m_APIMap;
	bool m_Initialized;
};