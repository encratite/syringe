#include <iostream>
#include <string>

#include <ail/types.hpp>

#include <boost/foreach.hpp>

#include <windows.h>

STARTUPINFO clear_startup_info()
{
	STARTUPINFO startup_info;

	//nasty
	std::memset(&startup_info, 0, sizeof(STARTUPINFO));
	startup_info.cb = sizeof(STARTUPINFO);

	return startup_info;
}

bool perform_injection(std::string const & executable_path, std::string const & working_directory, std::string const & module_path, string_vector const & arguments)
{
	STARTUPINFO startup_info = clear_startup_info();
	PROCESS_INFORMATION process_information;

	std::string command_line;
	BOOST_FOREACH(std::string const & argument, arguments)
		command_line += " " + argument;

	BOOL create_process_success = CreateProcess(executable_path.c_str(), const_cast<LPSTR>(command_line.c_str()), 0, 0, 0, CREATE_SUSPENDED, 0, working_directory.c_str(), &startup_info, &process_information);
	if(create_process_success == 0)
	{
		std::cout << "Failed to create the process: " << GetLastError() << std::endl;
		return false;
	}

	std::size_t string_size = module_path.length() + 1;

	LPVOID allocation = VirtualAllocEx(process_information.hProcess, 0, string_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(allocation == 0)
	{
		std::cout << "Failed to allocate memory for the library path: " << GetLastError() << std::endl;
		return false;
	}

	if(WriteProcessMemory(process_information.hProcess, allocation, module_path.c_str(), string_size, 0) == 0)
	{
		std::cout << "Failed to write to process memory: " << GetLastError() << std::endl;
		return false;
	}
	
	HMODULE module_handle = GetModuleHandle("kernel32.dll");
	if(module_handle == 0)
	{
		std::cout << "Failed to retrieve the kernel module handle: " << GetLastError() << std::endl;
		return false;
	}

	void * load_library = reinterpret_cast<void *>(GetProcAddress(module_handle, "LoadLibraryA"));
	if(load_library == 0)
	{
		std::cout << "Failed to retrieve the process address of LoadLibraryA: " << GetLastError() << std::endl;
		return false;
	}

	DWORD thread_id;
	HANDLE remote_thread = CreateRemoteThread(process_information.hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(load_library), allocation, 0, &thread_id);
	if(remote_thread == NULL)
	{
		std::cout << "Failed to create remote thread: " << GetLastError() << std::endl;
		return false;
	}

	if(WaitForSingleObject(remote_thread, INFINITE) == WAIT_FAILED)
	{
		std::cout << "Failed to wait for the termination of the remote thread: " << GetLastError() << std::endl;
		return false;
	}

	if(ResumeThread(process_information.hThread) == -1)
	{
		std::cout << "Failed to resume main thread " << process_information.hThread << " in the target process: " << GetLastError() << std::endl;
		return false;
	}

	CloseHandle(process_information.hProcess);
	CloseHandle(process_information.hThread);

	return true;
}

void print_usage(char ** argv)
{
	std::cout << "Usage:" << std::endl;
	std::cout << argv[0] << " <path to executable> <working directory> <path to module to inject> <arguments to pass to the executable>" << std::endl;
}

int main(int argc, char ** argv)
{
	if(argc < 4)
	{
		print_usage(argv);
		return 1;
	}

	std::string
		executable_path = argv[1],
		working_directory = argv[2],
		module_path = argv[3];

	string_vector arguments;
	for(int i = 4; i < argc; i++)
		arguments.push_back(argv[i]);

	if(!perform_injection(executable_path, working_directory, module_path, arguments))
		return 1;

	return 0;
}
