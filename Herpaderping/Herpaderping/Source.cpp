#include <Windows.h>
#include <iostream>
#include "Herpaderping.h"

constexpr auto HELP_NUMBER_OF_ARGS = 2;
constexpr auto NORMAL_NUMBER_OF_ARGS = 4;
constexpr auto ARGS_POSITION_SOURCE_EXECUTABLE = 1;
constexpr auto ARGS_POSITION_TARGET_EXECUTABLE = 2;
constexpr auto ARGS_POSITION_COVER_EXECUTABLE = 3;

struct CmdlineArguments {
	std::wstring source_executable;
	std::wstring target_executable;
	std::wstring cover_exectuable;
};

std::wstring string_to_wstring(const std::string& string)
{
	return std::wstring(string.begin(), string.end());
}

bool is_file_exists(const std::string& path)
{
	auto dwAttrib = GetFileAttributesA(path.c_str());
	return (dwAttrib != INVALID_FILE_ATTRIBUTES && !(dwAttrib & FILE_ATTRIBUTE_DIRECTORY));
}

void print_help()
{
	std::cout << std::endl << "##### Herpaderping v1.0.0 #####" << std::endl;
	std::cout << "Usage: herpaderping.exe source_executable target_executable cover_executable" << std::endl;
	std::cout << std::endl << "source_executable: path to the executable you wish to run." << std::endl;
	std::cout << "target_executable: path to where the source executable will be copied to and run from." << std::endl;
	std::cout << "cover_executable: path to the executable that will be used as a \"cover\" for our process." << std::endl;
	std::cout << std::endl << "Example:" << std::endl;
	std::cout << "Running cmd.exe with the cover of chrome.exe:" << std::endl;
	std::cout << "   herpaderping.exe \"C:\\Windows\\System32\\cmd.exe\" \".\\target.exe\" \"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe\"" << std::endl;
}

std::unique_ptr<CmdlineArguments> parse_program_arguments(int argc, char** argv)
{
	std::unique_ptr<CmdlineArguments> cmdline_args = nullptr;

	std::string source_exe_path = "";
	std::string target_exe_path = "";
	std::string cover_exe_path = "";

	switch (argc) {
	case NORMAL_NUMBER_OF_ARGS:
		source_exe_path = std::string(argv[ARGS_POSITION_SOURCE_EXECUTABLE]);
		target_exe_path = std::string(argv[ARGS_POSITION_TARGET_EXECUTABLE]);
		cover_exe_path = std::string(argv[ARGS_POSITION_COVER_EXECUTABLE]);

		if (!is_file_exists(source_exe_path)) {
			throw std::invalid_argument(source_exe_path + ": No such file or directory.");
		}

		if (!is_file_exists(cover_exe_path)) {
			throw std::invalid_argument(source_exe_path + ": No such file or directory.");
		}

		cmdline_args = std::make_unique<CmdlineArguments>();
		cmdline_args->source_executable = string_to_wstring(source_exe_path);
		cmdline_args->target_executable = string_to_wstring(target_exe_path);
		cmdline_args->cover_exectuable = string_to_wstring(cover_exe_path);

		break;

	default:
		throw std::invalid_argument("invalid number of arguments (got "
			+ std::to_string(argc) + " while expecting " + std::to_string(NORMAL_NUMBER_OF_ARGS) + ").");
	}

	return cmdline_args;
}

int main(int argc, char **argv)
{	
	std::unique_ptr<CmdlineArguments> cmdline_args = nullptr;

	try {
		cmdline_args = parse_program_arguments(argc, argv);
	}
	catch (const std::invalid_argument& exc) {
		std::cout << std::endl << "Error: " + std::string(exc.what()) << std::endl;
		print_help();
		goto failure;
	}

	try {
		auto herpaderping = Herpaderping(cmdline_args->source_executable, 
										 cmdline_args->target_executable, 
										 cmdline_args->cover_exectuable);

		herpaderping.run_process_with_cover();
	}
	catch (const std::runtime_error& exc) {
		std::cout << std::endl << "Error: " + std::string(exc.what()) << std::endl;
		goto failure;
	}

	return EXIT_SUCCESS;

failure:
	return EXIT_FAILURE;
}