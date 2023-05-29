#pragma once

#include <string>

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
	Process m_Process;
	PE m_File;

};