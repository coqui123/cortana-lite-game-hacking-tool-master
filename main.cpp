#include <Windows.h>
//#include <normie/util_crip_shit.hpp>
#include <misc/logger.h>
#include <epic/process.h>
#include <epic/thread.h>
#include <epic/hardware_breakpoint.h>
#include <epic/loader.h>
#include <epic/driver.h>
#include <epic/syscall.h>
#include <epic/cpuid.h>
#include <epic/memory_scanner.h>
#include <epic/shellcode.h>

#include <misc/fnv_hash.h>
#include <misc/vector.h>
#include <misc/scope_guard.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <TlHelp32.h>

#pragma comment(lib,"UrlMon.lib")

//credits to jono nation for mango nation
//normie did this nation
//inquires on mango::utils_crip_shit module will most likely me ignored out of frogulations and a bunch of capulation. . .

namespace frog::utils
{
	bool is_in_string(std::string str, std::string search_query)
	{
		return (!(str.find(search_query) != std::string::npos));
	}

	//setting up std::string variables for the nation
	std::unordered_map<std::string, std::string> string_unordered_map{
		{
			{enc_str(R"(dll-name)"), R"()"}, //name of a dll file
			{enc_str(R"(executable-name)"), R"()"}, //name of an executable
			{enc_str(R"(in-same-directory)"), R"()"}, //value which determines if its in the same directory
			{enc_str(R"(path)"), R"()"}, //a path in a directory nation
			{enc_str(R"(copy-path)"), R"()"}, //a path in a directory nation
			{enc_str(R"(initial-option)"), R"()"}, //option which is used to start the functions/features
			{enc_str(R"(folder-name)"), enc_str(R"(normie folder)")}, //name of folder where file is located
			{enc_str(R"(file-name)"), enc_str(R"(file name)")}, //file name
			{enc_str(R"(server-ip)"), enc_str(R"(sample.ip.net)")}, //file name
			{enc_str(R"(process-name)"), R"()"}, //file name
			{enc_str(R"(executable-path)"), R"()"}, //file name
			{enc_str(R"(download-path)"), R"()"}, //file name
			{enc_str(R"(download-url)"), R"()"}, //file name
			{enc_str(R"(hdd-id)"), R"()"}, //file name
			{enc_str(R"(hardware-id)"), R"()"}, //file name
			{enc_str(R"(home-directory)"), enc_str(R"(C:\\cortana)")}, //file name
		}
	};

	std::string get_first_hdd_serial_number() // gets computer serial #
	{
		//get a handle to the first physical drives
		const HANDLE h = CreateFileW(L"\\\\.\\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE, nullptr,
		                             OPEN_EXISTING,
		                             0, nullptr);
		if (h == INVALID_HANDLE_VALUE) return {};
		//an std::unique_ptr is used to perform cleanup automatically when returning (i.e. to avoid code duplication)
		const std::unique_ptr<std::remove_pointer<HANDLE>::type, void(*)(HANDLE)> h_device{
			h, [](HANDLE handle) { CloseHandle(handle); }
		};
		//initialize a STORAGE_PROPERTY_QUERY data structure (to be used as input to DeviceIoControl)
		STORAGE_PROPERTY_QUERY storage_property_query{};
		storage_property_query.PropertyId = StorageDeviceProperty;
		storage_property_query.QueryType = PropertyStandardQuery;
		//initialize a STORAGE_DESCRIPTOR_HEADER data structure (to be used as output from DeviceIoControl)
		STORAGE_DESCRIPTOR_HEADER storage_descriptor_header{};
		//the next call to DeviceIoControl retrieves necessary size (in order to allocate a suitable buffer)
		//call DeviceIoControl and return an empty std::string on failure
		DWORD dw_bytes_returned = 0;
		if (!DeviceIoControl(h_device.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storage_property_query,
		                     sizeof(STORAGE_PROPERTY_QUERY),
		                     &storage_descriptor_header, sizeof(STORAGE_DESCRIPTOR_HEADER), &dw_bytes_returned,
		                     nullptr))
			return {};
		//allocate a suitable buffer
		const DWORD dw_out_buffer_size = storage_descriptor_header.Size;
		const std::unique_ptr<BYTE[]> p_out_buffer{new BYTE[dw_out_buffer_size]{}};
		//call DeviceIoControl with the allocated buffer
		if (!DeviceIoControl(h_device.get(), IOCTL_STORAGE_QUERY_PROPERTY, &storage_property_query,
		                     sizeof(STORAGE_PROPERTY_QUERY),
		                     p_out_buffer.get(), dw_out_buffer_size, &dw_bytes_returned, nullptr))
			return {};
		//read and return the serial number out of the output buffer
		STORAGE_DEVICE_DESCRIPTOR* const p_device_descriptor = reinterpret_cast<STORAGE_DEVICE_DESCRIPTOR*>(p_out_buffer
			.get());
		const DWORD serial_number_offset = p_device_descriptor->SerialNumberOffset;
		if (serial_number_offset == 0) return {};
		std::string serial_number = std::to_string(serial_number_offset);
		return serial_number;
	}

	void download_file(std::string download_url, std::string save_path) //downloads file
	{
		if (std::filesystem::exists(save_path))
			return;

		URLDownloadToFileA(nullptr, download_url.c_str(), save_path.c_str(), 0, nullptr);
		mango::logger.success(enc_str(R"(File Downloaded. . .)"));
	}
}

namespace frog::init
{
	void get_option()
	{
		mango::logger.info(enc_str(R"(Cortana multi nation formulated by normie nation)"));
		if (!std::filesystem::exists(frog::utils::string_unordered_map[enc_str(R"(home-directory)")]))
		{
			std::filesystem::create_directory(frog::utils::string_unordered_map[enc_str(R"(home-directory)")]);
		}
		mango::logger.info(enc_str(R"(What would you like to do? inject : load : hwid )"));
		std::cin >> frog::utils::string_unordered_map[enc_str(R"(initial-option)")];
	}
}

namespace frog
{
	void inject_into_process()
	{
		if (!(frog::utils::string_unordered_map[enc_str(R"(initial-option)")] == enc_str(
			R"(inject)")))
			return;

		mango::logger.info(enc_str(R"(Please input what process u want to inject into. . .)"));
		std::cin >> frog::utils::string_unordered_map[enc_str(R"(process-name)")];
		if (frog::utils::is_in_string(frog::utils::string_unordered_map[enc_str(R"(process-name)")],
		                              enc_str(R"(.exe)")))
		{
			frog::utils::string_unordered_map[enc_str(R"(process-name)")] += enc_str(R"(.exe)");
		}
		const mango::Process process{
			mango::Process::get_pid_by_name(frog::utils::string_unordered_map[enc_str(R"(process-name)")])
		};
		mango::logger.info(enc_str(R"(Process name is: )") + process.get_name());
		mango::logger.info(enc_str(R"(Process id is: )") + std::to_string(process.get_pid()));
		mango::logger.info(enc_str(R"(Please input your dll name. . .)"));
		std::cin >> frog::utils::string_unordered_map[enc_str(R"(dll-name)")];
		if (frog::utils::is_in_string(
			frog::utils::string_unordered_map[enc_str(R"(dll-name)")], enc_str(R"(.dll)")))
		{
			frog::utils::string_unordered_map[enc_str(R"(dll-name)")] += enc_str(R"(.dll)");
		}
		
		mango::logger.info(enc_str(R"(Dll name is: )") + frog::utils::string_unordered_map[enc_str(R"(dll-name)")]);

		if (!std::filesystem::exists(frog::utils::string_unordered_map[enc_str(R"(dll-name)")]))
		{
			mango::logger.info(enc_str(R"(Please input your dll path. . .)"));
			std::cin >> frog::utils::string_unordered_map[enc_str(R"(path)")];
			mango::logger.info(enc_str(R"(Injecting into )") + process.get_name() + enc_str(R"( . . .)"));
			manual_map(process, frog::utils::string_unordered_map[enc_str(R"(path)")]);
		}
		else
		{
			frog::utils::string_unordered_map[enc_str(R"(path)")] = std::filesystem::current_path()
				.string() + enc_str(R"(\)") + frog::utils::string_unordered_map[enc_str(
					R"(dll-name)")];
			mango::logger.info(enc_str(R"(Injecting into )") + process.get_name() + enc_str(R"( . . .)"));
			manual_map(process, frog::utils::string_unordered_map[enc_str(R"(path)")]);
		}
		mango::logger.success(
			enc_str(R"(Injected into )") + process.get_name() + enc_str(R"( successfully )") + enc_str(R"(. . .)"));
	}

	void hardware_id()
	{
		if (!(frog::utils::string_unordered_map[enc_str(R"(initial-option)")] == enc_str(R"(hwid)")
			))
			return;

		const auto hdd_id{ frog::utils::get_first_hdd_serial_number() };
		frog::utils::string_unordered_map[enc_str(R"(hardware-id)")] = std::to_string(
			std::stoi(hdd_id) * std::atoi(enc_str(R"(5)").c_str()));
		mango::logger.info(
			enc_str(R"(Your hwid is )") + frog::utils::string_unordered_map[enc_str(R"(hardware-id)")] + enc_str(
				R"( . . .)"));
	}
	
	void load()
	{
		if (!(frog::utils::string_unordered_map[enc_str(R"(initial-option)")] == enc_str(R"(load)")
		))
			return;
		const mango::Process process{ mango::Process::get_pid_by_name(enc_str(R"(csgo.exe)")) };
		if (std::filesystem::exists(enc_str(R"(C:\\cortana\build.dll)")))
		{
			std::filesystem::remove(enc_str(R"(C:\\cortana\build.dll)"));
			mango::logger.info(enc_str(R"(Refreshing build. . .)"));
		}
		if (!std::filesystem::exists(enc_str(R"(C:\\cortana\build.dll)")))
		{
			// downloads the file from a url so use github and upload a file and then download it or something to test it out
			frog::utils::download_file(
				enc_str(
					R"(https://github.com/coqui123/ayyware_remastered_V2/blob/master/CSGOSimple-master/SimpleInjector/build.dll?raw=true)"),
				enc_str(R"(C:\\cortana\build.dll)"));

			return;
		}
		manual_map(process, enc_str(R"(C:\\cortana\build.dll)"));
		mango::logger.success(
			enc_str(R"(Injected into )") + process.get_name() + enc_str(R"( successfully )") + enc_str(R"(. . .)"));
	}
}

int main()
{
	mango::logger.set_channels(mango::basic_colored_logging());
	try
	{
		frog::init::get_option();
		frog::hardware_id();
		frog::inject_into_process();
		frog::load();
	}
	catch (const std::exception& e)
	{
		mango::logger.error(e.what());
	}

	std::system(R"(pause)");
	return 0;
}
