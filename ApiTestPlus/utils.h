#pragma once
#include <Windows.h>
#include <string>
#include <time.h>
#include <ctime>
#pragma warning(disable : 4996)

namespace Utilities
{
	void Kill()
	{
		Beep(300, 500);
		exit(0);
	}

	const std::string CurrentDateTime()
	{
		time_t     now = time(0);
		struct tm  tstruct;
		char       buf[80];
		tstruct = *localtime(&now);
		strftime(buf, sizeof(buf), "%m/%d/%y %X", &tstruct);

		return buf;
	}

	std::string tm_to_readable_time2(tm ctx)
	{
		char buffer[80];

		strftime(buffer, sizeof(buffer), "%m/%d/%y %H:%M:%S", &ctx);

		return std::string(buffer);
	}

	std::string tm_to_readable_time(tm ctx)
	{
		char buffer[80];

		strftime(buffer, sizeof(buffer), "%a %m/%d/%y %H:%M:%S %Z", &ctx);

		return std::string(buffer);
	}

	static std::time_t string_to_timet(std::string timestamp)
	{
		auto cv = strtol(timestamp.c_str(), NULL, 10); // long

		return (time_t)cv;
	}

	static std::tm timet_to_tm(time_t timestamp)
	{
		std::tm context;

		localtime_s(&context, &timestamp);

		return context;
	}

	std::string removeQuotesFromString(std::string s)
	{
		if (s.front() == '"')
		{
			s.erase(0, 1); // erase the first character
			s.erase(s.size() - 1); // erase the last character
		}
		return s;
	}

	std::string getExeHandle()
	{
		auto mHandle = GetModuleHandle(NULL);
		std::stringstream ss;
		ss << mHandle;
		std::string stringHandle = ss.str();
		return stringHandle;
	}

	std::string GetExeFileName()
	{
		WCHAR path[MAX_PATH] = { 0 };
		GetModuleFileName(NULL, path, MAX_PATH);
		std::wstring ws(path);
		std::string str(ws.begin(), ws.end());
		return str;
	}

	std::string GetExePath()
	{
		std::string f = GetExeFileName();
		return f.substr(0, f.find_last_of("\\/"));
	}
}