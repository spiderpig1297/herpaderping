#pragma once

#include <Windows.h>

class HandleGuard final
{
public:
	HandleGuard();
	HandleGuard(HANDLE handle);
	~HandleGuard();

	void set(HANDLE new_handle);
	HANDLE get() const;

private:
	HANDLE m_handle;
};

