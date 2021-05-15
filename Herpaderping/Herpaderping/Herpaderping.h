#pragma once

#include <vector>
#include "NtdllFunctions.h"

class Herpaderping
{
public:
	Herpaderping(std::string path_to_source, std::string path_to_target, std::string path_to_cover);

	void run_process_with_cover();

protected:
	void read_source_payload();
	void create_target_file_and_write_payload();
	void create_target_process();
	void cover_target_file();
	void create_and_run_target_main_thread();

	HANDLE section_handle;
	HANDLE target_process;
	HANDLE target_file;
	std::unique_ptr<std::vector<char>> source_file_payload;

	std::unique_ptr<NtdllFunctions> ntdll_functions;
	std::string path_to_source;
	std::string path_to_target;
	std::string path_to_cover;
};
