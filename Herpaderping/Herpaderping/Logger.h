#pragma once

#include <vector>
#include <string>
#include <memory>

class IOutputStream
{
public:
	virtual void write(const std::string& message) = 0;
};

class ConsoleOutputStream : public IOutputStream
{
public:
	ConsoleOutputStream() = default;
	virtual void write(const std::string& message) override;
};

enum class LoggerSeverity {
	SEV_DEBUG = 1,
	SEV_INFO,
	SEV_ERROR,
	SEV_CRITICAL
};

class Logger
{
public:
	Logger(LoggerSeverity minimum_severity, const std::vector<std::shared_ptr<IOutputStream>>& streams);

	void info(const std::string& message);
	void error(const std::string& message);
	void critical(const std::string& message);

protected:
	void _log(LoggerSeverity severity, const std::string& message);
	void _write_message_to_all_streams(const std::string& message);
	std::string _get_current_timestamp() const;
	std::string _get_severity_name(LoggerSeverity severity) const;

	LoggerSeverity m_minimum_severity;
	std::vector<std::shared_ptr<IOutputStream>> m_streams;
};

extern std::shared_ptr<Logger> g_logger;
