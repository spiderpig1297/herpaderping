#include "HandleGuard.h"

HandleGuard::HandleGuard()
{ }

HandleGuard::HandleGuard(HANDLE handle) : m_handle(handle)
{ }

HandleGuard::~HandleGuard()
{
	// Best effort, return value is ignored.
	CloseHandle(m_handle);
}

void HandleGuard::set(HANDLE new_handle)
{
	m_handle = new_handle;
}

HANDLE HandleGuard::get() const
{
	return m_handle;
}

