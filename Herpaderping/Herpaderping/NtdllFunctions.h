#pragma once

#include <Windows.h>
#include "ntdll_types.h"
#include "Utils.h"

using NtCreateSectionDef = NTSTATUS(NTAPI*)(
	OUT PHANDLE, 
	IN ULONG, 
	IN POBJECT_ATTRIBUTES OPTIONAL, 
	IN PLARGE_INTEGER OPTIONAL, 
	IN ULONG, IN ULONG, 
	IN HANDLE OPTIONAL);

using NtCreateProcessExDef = NTSTATUS(NTAPI*)(
	OUT PHANDLE, 
	IN ACCESS_MASK, 
	IN POBJECT_ATTRIBUTES OPTIONAL, 
	IN HANDLE, 
	IN ULONG, 
	IN HANDLE, 
	IN HANDLE, 
	IN HANDLE, 
	IN BOOLEAN);

using RtlCreateProcessParametersExDef = NTSTATUS(NTAPI*)(
	_Out_ PRTL_USER_PROCESS_PARAMETERS* pProcessParameters,
	_In_ PUNICODE_STRING ImagePathName,
	_In_opt_ PUNICODE_STRING DllPath,
	_In_opt_ PUNICODE_STRING CurrentDirectory,
	_In_opt_ PUNICODE_STRING CommandLine,
	_In_opt_ PVOID Environment,
	_In_opt_ PUNICODE_STRING WindowTitle,
	_In_opt_ PUNICODE_STRING DesktopInfo,
	_In_opt_ PUNICODE_STRING ShellInfo,
	_In_opt_ PUNICODE_STRING RuntimeData,
	_In_ ULONG Flags);

using RtlInitUnicodeStringDef = VOID(NTAPI*)(
	PUNICODE_STRING DestinationString,
	PCWSTR SourceString);

using NtQueryInformationProcessDef = NTSTATUS(NTAPI*)(
	IN HANDLE ProcessHandle,
	IN PROCESSINFOCLASS ProcessInformationClass,
	OUT PVOID ProcessInformation,
	IN ULONG ProcessInformationLength,
	OUT PULONG ReturnLength OPTIONAL);

using NtCreateThreadExDef = NTSTATUS(NTAPI*)(
	OUT PHANDLE hThread,
	IN ACCESS_MASK DesiredAccess,
	IN PVOID ObjectAttributes,
	IN HANDLE ProcessHandle,
	IN PVOID lpStartAddress,
	IN PVOID lpParameter,
	IN ULONG Flags,
	IN SIZE_T StackZeroBits,
	IN SIZE_T SizeOfStackCommit,
	IN SIZE_T SizeOfStackReserve,
	OUT PVOID lpBytesBuffer);

class NtdllFunctions final
{
public:
	NtdllFunctions();
	~NtdllFunctions(); 

	NtdllFunctions(const NtdllFunctions&) = delete;
	NtdllFunctions(const NtdllFunctions&&) = delete;

	NtCreateSectionDef NtCreateSection;
	NtCreateProcessExDef NtCreateProcessEx;
	RtlCreateProcessParametersExDef RtlCreateProcessParametersEx;
	NtQueryInformationProcessDef NtQueryInformationProcess;
	RtlInitUnicodeStringDef RtlInitUnicodeString;
	NtCreateThreadExDef NtCreateThreadEx;

private:
	FARPROC _get_function_address(LPCSTR function_name) const;

	HMODULE library_handle;
};

