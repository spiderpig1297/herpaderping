#include "utils.h"

std::string error_to_str(DWORD error)
{
	std::ostringstream stream;
	stream << error;
	return stream.str();
}
