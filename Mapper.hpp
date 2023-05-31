#pragma once

#include <string>
#include <vector>

#include "PE/PE.hpp"
#include "Process/Process.hpp"

class Mapper
{
public:
	bool SelectProcess(const std::string& targetProcess);
	bool SelectFile(const std::string& filePath);

public:
	bool MapImage();

private:
	bool executeMain(uint64_t entry);

private:
	std::vector<uint8_t> QWORDToBytes(uint64_t qword);

private:
	Process m_Process;
	PE m_File;

};