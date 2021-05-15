#include "utils.h"

std::string error_to_str(DWORD error)
{
	std::ostringstream stream;
	stream << error;
	return stream.str();
}

std::wstring string_to_wstring(std::string s)
{
	return std::wstring(s.begin(), s.end());
}
