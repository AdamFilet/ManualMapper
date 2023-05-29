#include "Process.hpp"
#include "ProcessHelpers.hpp"

Process::~Process()
{
	if (m_Handle != nullptr && m_Handle != INVALID_HANDLE_VALUE)
	{
		CloseHandle(m_Handle);
	}
}

bool Process::Attach(const std::string& processName)
{
	m_Pid = ProcessHelpers::GetProcessID(processName);
	if (m_Pid == 0)
	{
		return false;
	}

	m_Handle = OpenProcess(PROCESS_ALL_ACCESS, 0, m_Pid);
	if (m_Handle == nullptr || m_Handle == INVALID_HANDLE_VALUE)
	{
		return false;
	}

	m_Name = processName;
}

bool Process::Read(void* address, void* value, size_t size)
{
	return ReadProcessMemory(this->m_Handle, address, value, size, nullptr);
}

bool Process::Write(void* address, const void* value, size_t size)
{
	return WriteProcessMemory(this->m_Handle, address, value, size, nullptr);
}
