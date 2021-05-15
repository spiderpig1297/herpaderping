#include <string>
#include <stdexcept>
#include "NtdllFunctions.h"

constexpr LPCSTR NTDLL_LIBRARY_NAME = "ntdll.dll";

FARPROC NtdllFunctions::_get_function_address(LPCSTR function_name) const
{
	FARPROC func_address = GetProcAddress(this->library_handle, function_name);
	if (!func_address) {
		throw std::runtime_error("GetProcAddress: failed to load address for function "
			+ std::string(function_name) +
			". Error: " + error_to_str(GetLastError()));
	}

	return GetProcAddress(this->library_handle, function_name);
}

NtdllFunctions::NtdllFunctions()
{
	this->library_handle = LoadLibraryA(NTDLL_LIBRARY_NAME);
	if (NULL == this->library_handle) {
		throw std::runtime_error("LoadLibraryA: failed to load ntdll.dll. Error: " + error_to_str(GetLastError()));
	}

	this->NtCreateProcessEx = (NtCreateProcessExDef)_get_function_address("NtCreateProcessEx");
	this->NtCreateThreadEx = (NtCreateThreadExDef)_get_function_address("NtCreateThreadEx");
	this->NtCreateSection = (NtCreateSectionDef)_get_function_address("NtCreateSection");
	this->NtQueryInformationProcess = (NtQueryInformationProcessDef)_get_function_address("NtQueryInformationProcess");
	this->RtlInitUnicodeString = (RtlInitUnicodeStringDef)_get_function_address("RtlInitUnicodeString");
	this->RtlCreateProcessParametersEx = (RtlCreateProcessParametersExDef)_get_function_address("RtlCreateProcessParametersEx");
}

NtdllFunctions::~NtdllFunctions()
{
	FreeLibrary(this->library_handle);
}