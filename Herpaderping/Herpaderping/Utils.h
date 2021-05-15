#pragma once

#include <sstream>
#include <string>
#include <Windows.h>

std::string error_to_str(DWORD error); 

std::wstring string_to_wstring(std::string s);