#include <Windows.h>
#include <iostream>
#include "Herpaderping.h"

constexpr auto HELP_NUMBER_OF_ARGS = 2;
constexpr auto NORMAL_NUMBER_OF_ARGS = 4;
constexpr auto SOURCE_EXECUTABLE_ARGS_POSITION = 1;
constexpr auto TARGET_EXECUTABLE_ARGS_POSITION = 2;
constexpr auto COVER_EXECUTABLE_ARGS_POSITION = 3;

struct CmdlineArguments {
	std::wstring source_executable;
	std::wstring target_executable;
	std::wstring cover_exectuable;
};

std::wstring string_to_wstring(const std::string& string)
{
	return std::wstring(string.begin(), string.end());
}

void print_help()
{
	return;
}

// constexpr auto PATH_TO_COVER = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";
std::unique_ptr<CmdlineArguments> parse_program_arguments(int argc, char** argv)
{
	std::unique_ptr<CmdlineArguments> cmdline_args = nullptr;

	switch (argc) {
	case HELP_NUMBER_OF_ARGS:
		// TODO: check if it is -h.
		print_help();
		break;

	case NORMAL_NUMBER_OF_ARGS:
		cmdline_args = std::make_unique<CmdlineArguments>();
		cmdline_args->source_executable = string_to_wstring(std::string(argv[SOURCE_EXECUTABLE_ARGS_POSITION]));
		cmdline_args->target_executable = string_to_wstring(std::string(argv[TARGET_EXECUTABLE_ARGS_POSITION]));
		cmdline_args->cover_exectuable = string_to_wstring(std::string(argv[COVER_EXECUTABLE_ARGS_POSITION]));
		break;

	default:
		print_help();
		throw std::invalid_argument("Invalid number of arguments (" + std::to_string(argc)
			+ "), expected " + std::to_string(NORMAL_NUMBER_OF_ARGS));
	}

	return cmdline_args;
}

int main(int argc, char **argv)
{	
	try {
		auto cmdline_args = parse_program_arguments(argc, argv);

		auto herpaderping = Herpaderping(cmdline_args->source_executable, 
										 cmdline_args->target_executable, 
										 cmdline_args->cover_exectuable);

		herpaderping.run_process_with_cover();
	}
	catch (const std::exception& exc) {
		std::cout << "Exception: " + std::string(exc.what()) << std::endl;
		return EXIT_FAILURE;
	}

	return EXIT_SUCCESS;
}