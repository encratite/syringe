#include <iostream>
#include <string>
#include <vector>

#include <boost/foreach.hpp>

#include <Windows.h>

STARTUPINFO clearStartupInfo()
{
	STARTUPINFO startupInfo;

	//nasty
	std::memset(&startupInfo, 0, sizeof(STARTUPINFO));
	startupInfo.cb = sizeof(STARTUPINFO);

	return startupInfo;
}

bool performInjection(std::string const & executable_path, std::string const & working_directory, std::string const & module_path, std::vector<std::string> const & arguments)
{
	STARTUPINFO startupInfo = clearStartupInfo();
	PROCESS_INFORMATION processInformation;

	std::string commandLine = "\"" + executable_path + "\"";
	BOOST_FOREACH(std::string const & argument, arguments)
		commandLine += " \"" + argument + "\"";

	BOOL createProcessSuccess = CreateProcess(executable_path.c_str(), const_cast<LPSTR>(commandLine.c_str()), 0, 0, 0, CREATE_SUSPENDED, 0, working_directory.c_str(), &startupInfo, &processInformation);
	if(createProcessSuccess == 0)
	{
		std::cout << "Failed to create the process: " << GetLastError() << std::endl;
		return false;
	}

	std::size_t stringSize = module_path.length() + 1;

	LPVOID allocation = VirtualAllocEx(processInformation.hProcess, 0, stringSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(allocation == 0)
	{
		std::cout << "Failed to allocate memory for the library path: " << GetLastError() << std::endl;
		return false;
	}

	if(WriteProcessMemory(processInformation.hProcess, allocation, module_path.c_str(), stringSize, 0) == 0)
	{
		std::cout << "Failed to write to process memory: " << GetLastError() << std::endl;
		return false;
	}
	
	HMODULE moduleHandle = GetModuleHandle("kernel32.dll");
	if(moduleHandle == 0)
	{
		std::cout << "Failed to retrieve the kernel module handle: " << GetLastError() << std::endl;
		return false;
	}

	void * loadLibrary = reinterpret_cast<void *>(GetProcAddress(moduleHandle, "LoadLibraryA"));
	if(loadLibrary == 0)
	{
		std::cout << "Failed to retrieve the process address of LoadLibraryA: " << GetLastError() << std::endl;
		return false;
	}

	DWORD threadId;
	HANDLE remoteThread = CreateRemoteThread(processInformation.hProcess, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary), allocation, 0, &threadId);
	if(remoteThread == NULL)
	{
		std::cout << "Failed to create remote thread: " << GetLastError() << std::endl;
		return false;
	}

	if(WaitForSingleObject(remoteThread, INFINITE) == WAIT_FAILED)
	{
		std::cout << "Failed to wait for the termination of the remote thread: " << GetLastError() << std::endl;
		return false;
	}

	if(ResumeThread(processInformation.hThread) == -1)
	{
		std::cout << "Failed to resume main thread " << processInformation.hThread << " in the target process: " << GetLastError() << std::endl;
		return false;
	}

	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);

	return true;
}

void printUsage(char ** argv)
{
	std::cout << "Usage:" << std::endl;
	std::cout << argv[0] << " <path to executable> <working directory> <path to module to inject> <arguments to pass to the executable>" << std::endl;
}

int main(int argc, char ** argv)
{
	std::cout << "Arguments:" << std::endl;
	for(int i = 0; i < argc; i++)
		std::cout << i << ": \"" << argv[i] << "\"" << std::endl;

	if(argc < 4)
	{
		printUsage(argv);
		return 1;
	}

	std::string
		executablePath = argv[1],
		workingDirectory = argv[2],
		modulePath = argv[3];

        std::vector<std::string> arguments;
	for(int i = 4; i < argc; i++)
		arguments.push_back(argv[i]);

	std::cout << "Path to executable: " << executablePath << std::endl;
	std::cout << "Working directory: " << workingDirectory << std::endl;
	std::cout << "Path to the module to inject: " << modulePath << std::endl;

	if(!performInjection(executablePath, workingDirectory, modulePath, arguments))
		return 1;

	return 0;
}
