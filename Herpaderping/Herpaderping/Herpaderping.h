#pragma once

#include <vector>
#include "NtdllFunctions.h"
#include "HandleGuard.h"

constexpr auto DEFAULT_WINDOWS_STATION = L"WinSta0\\Default";

class Herpaderping
{
public:
	/**
	 * @param path_to_source: source executable (will be copied to the target executable and will be executed).
	 * @param path_to_target: target exectuable; the process which will eventually be executed.
	 * @param path_to_cover: the executable that the target execuable will impersonate to.
	 */
	Herpaderping(std::wstring path_to_source, 
				 std::wstring path_to_target, 
				 std::wstring path_to_cover,
				 const wchar_t* windows_station_to_run_on=DEFAULT_WINDOWS_STATION);

	/**
	 * Runs the executable in path_to_source while "lying" that the content of the executable file
	 * is the one of the executable pointed by path_to_cover.
	 * @throws std::runtime_error
	 */
	void run_process_with_cover();

protected:
	/**
	 * Reads the content of the source executable and saves it to source_file_payload.
	 * @throws std::runtime_error
	 */
	void read_source_payload();

	/**
	 * Creates the target executable and copies the source payload to it.
	 * @throws std::runtime_error
	 */
	void create_target_file_and_write_payload();

	/**
	 * Creates the target process with an image section contains the target executable.
	 * @throws std::runtime_error
	 */
	void create_target_process();

	/**
	 * Overwrites the target executable file with the content of the cover executable.
	 * @throws std::runtime_error
	 */
	void cover_target_file();

	/**
	 * Create and runs the main thread of our created process.
	 * We do that seperately from the creation of the process since we want to overwrite the
	 * image on the disk in the middle, exploiting the Anti-Virus and preventing it from scanning
	 * our executable on the disk.
	 * @throws std::runtime_error
	 */
	void create_and_run_target_main_thread();

	std::wstring m_windows_station_to_run_on;
	std::unique_ptr<HandleGuard> m_section_handle;
	std::unique_ptr<HandleGuard> m_target_process;
	std::unique_ptr<HandleGuard> m_target_file;
	std::unique_ptr<HandleGuard> m_thread_handle;
	std::unique_ptr<std::vector<char>> m_source_file_payload;

	std::unique_ptr<NtdllFunctions> m_ntdll_functions;
	std::wstring m_path_to_source;
	std::wstring m_path_to_target;
	std::wstring m_path_to_cover;
};
