#include <iostream>
#include <string_view>
#include <Windows.h>
#include <TlHelp32.h>
#include <memory>
#include <cstdint>
#include <vector>
#include "injector.hpp"
#include "lazy.h"
#include "protection/antiDbg.h"


void DeleteKey(std::ifstream& File)
{

	std::string regfile("key.txt");
	std::ofstream(regfile, std::ios::trunc);
	File.setstate(std::ios::failbit);
	remove(regfile.c_str());
}

void sleepMilliseconds(int ms) {				
	std::this_thread::sleep_for(std::chrono::milliseconds(ms));
}

std::string tm_to_readable_time2(tm ctx) {
	SPOOF_FUNC

		std::time_t now = std::time(nullptr);
	std::time_t expiry = std::mktime(&ctx);

	double remainingSeconds = std::difftime(expiry, now);

	if (remainingSeconds >= 60 * 60 * 24) {
		int remainingDays = static_cast<int>(remainingSeconds / (60 * 60 * 24));
		return std::to_string(remainingDays) + " day(s).";
	}
	else if (remainingSeconds >= 60 * 60) {
		int remainingHours = static_cast<int>(remainingSeconds / (60 * 60));
		return std::to_string(remainingHours) + " hour(s).";
	}
	else {
		int remainingMinutes = static_cast<int>(remainingSeconds / 60);
		return std::to_string(remainingMinutes) + " minute(s).";
	}
}


static std::time_t string_to_timet(std::string timestamp) {
	SPOOF_FUNC

		auto cv = strtol(timestamp.c_str(), NULL, 10); // long

	return (time_t)cv;
}

static std::tm timet_to_tm(time_t timestamp) {
	SPOOF_FUNC

		std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}

std::string readFileIntoString(const std::string& path) {
	SPOOF_FUNC

		auto ss = std::ostringstream{};
	std::ifstream input_file(path);
	if (!input_file.is_open()) {
		std::cerr << E("Could Not Open License Key File") << std::endl;
		exit(EXIT_FAILURE);
	}
	ss << input_file.rdbuf();
	return ss.str();
}

int main()
{
	
	
																																																							აპლიკაცია.init();
MessageBox(NULL, "Press OK In Lobby", "Inject", MB_OK | MB_ICONINFORMATION);

pysen(E("UnrealWindow"),L"nuh uh");



	exit(0);
}

