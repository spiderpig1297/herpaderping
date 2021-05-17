#include "Logger.h"

#include <sstream>
#include <iostream>
#include <iomanip>

std::shared_ptr<Logger> g_logger = nullptr;

void ConsoleOutputStream::write(const std::string& message)
{
	std::cout << std::string(message.data()) << std::endl;
}

Logger::Logger(LoggerSeverity minimum_severity, const std::vector<std::shared_ptr<IOutputStream>>& streams) :
	m_minimum_severity(minimum_severity),
	m_streams(streams)
{ }

void Logger::info(const std::string & message)
{
	_log(LoggerSeverity::SEV_INFO, message);
}

void Logger::error(const std::string& message)
{
	_log(LoggerSeverity::SEV_ERROR, message);
}

void Logger::critical(const std::string& message)
{
	_log(LoggerSeverity::SEV_CRITICAL, message);
}

void Logger::_log(LoggerSeverity severity, const std::string& message)
{
	auto current_timestamp_as_str = _get_current_timestamp();
	auto severity_name_as_str = _get_severity_name(severity);
	auto string_message = "[" + current_timestamp_as_str + "] " + severity_name_as_str + ": " + message;

	_write_message_to_all_streams(string_message);
}

std::string Logger::_get_current_timestamp() const
{
	auto t = std::time(nullptr);
#pragma warning(disable:4996)
	auto tm = *std::localtime(&t);
	std::ostringstream oss;
	oss << std::put_time(&tm, "%H:%M:%S");
	return oss.str();
}

std::string Logger::_get_severity_name(LoggerSeverity severity) const
{
	switch (severity) {
	case LoggerSeverity::SEV_DEBUG:
		return std::string("DEBUG");
	case LoggerSeverity::SEV_INFO:
		return std::string("INFO");
	case LoggerSeverity::SEV_ERROR:
		return std::string("ERROR");
	case LoggerSeverity::SEV_CRITICAL:
		return std::string("CRITICAL");
	default:
		return std::string("N/A");
	}
}

void Logger::_write_message_to_all_streams(const std::string& message)
{
	for (const auto& stream : m_streams) {
		try {
			stream->write(message);
		}
		catch (...) {
			// What can we do? log?
		}
	}
}

void g_set_global_logger(std::shared_ptr<Logger> logger)
{
	g_logger = logger;
}

std::shared_ptr<Logger> g_get_global_logger()
{
	if (!g_logger) {
		throw std::runtime_error("Error: tryring to access uninitialized logger.");
	}

	return g_logger;
}
