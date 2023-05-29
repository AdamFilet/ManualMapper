#pragma once

#include <string>
#include <cstdint>

class ProcessHelpers
{
public:
	static bool IsOpen(const std::string& processName);

public:
	static uint32_t GetProcessID(const std::string& processName);

};