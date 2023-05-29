#pragma once

#include <Windows.h>
#include <string>

class Process
{
public:
	~Process();

public:
	bool Attach(const std::string& processName);

public:
	template<typename T>
	bool Read(uintptr_t address, T& value)
	{
		return this->Read<T>(reinterpret_cast<void*>(address), value);
	}

	template<typename T>
	T Read(uintptr_t address)
	{
		return this->Read<T>(reinterpret_cast<void*>(address));
	}

	template<typename T>
	bool Read(void* address, T& value)
	{
		return this->Read(address, &value, sizeof(T));
	}

	template<typename T>
	T Read(void* address)
	{
		T value;
		if (!this->Read(address, &value, sizeof(T)))
		{
			return {};
		}

		return value;
	}

	template<typename T>
	bool Write(uintptr_t address, const T& value)
	{
		return this->Write(reinterpret_cast<void*>(address), &value, sizeof(T));
	}

public:
	bool Read(void* address, void* value, size_t size);
	bool Write(void* address, const void* value, size_t size);

public:
	uintptr_t AllocateMemory(uint32_t size, uint32_t allocationType, uint32_t allocationProtect);
	uintptr_t GetModuleAddress(const std::string& moduleBase);

public:
	uint32_t m_Pid;
	HANDLE m_Handle;
	std::string m_Name;

};