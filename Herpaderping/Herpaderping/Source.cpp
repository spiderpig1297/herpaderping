#include <Windows.h>
#include <iostream>
#include "Herpaderping.h"

constexpr auto PATH_TO_SOURCE = L"C:\\Windows\\System32\\cmd.exe";
constexpr auto PATH_TO_TARGET = L"C:\\Users\\idano\\Workspace\\Projects\\herpaderping\\Herpaderping\\x64\\Debug\\target.exe";
constexpr auto PATH_TO_COVER = L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe";

int main()
{	
	auto herpaderping = Herpaderping(std::wstring(PATH_TO_SOURCE), std::wstring(PATH_TO_TARGET), std::wstring(PATH_TO_COVER));

	try {
		herpaderping.run_process_with_cover();
	}
	catch (std::runtime_error& exc) {
		std::cout << "Exception: " + std::string(exc.what()) << std::endl;
		exit(1);
	}

	return 0;
}