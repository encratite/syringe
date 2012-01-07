#include <iostream>
#include <string>
#include <vector>

#include <boost/foreach.hpp>

#include <Windows.h>
#include <tlhelp32.h>

namespace
{
	std::string const
		suspendedLaunchArgument = "suspended-launch",
		runningProcessArgument = "running-process";
}

STARTUPINFO emptyStartupInfo()
{
	STARTUPINFO startupInfo;
	startupInfo.cb = sizeof(STARTUPINFO);
	startupInfo.lpReserved = NULL;
	startupInfo.lpDesktop = NULL;
	startupInfo.lpTitle = NULL;
	startupInfo.dwX = 0;
	startupInfo.dwY = 0;
	startupInfo.dwXSize = 0;
	startupInfo.dwYSize = 0;
	startupInfo.dwXCountChars = 0;
	startupInfo.dwYCountChars = 0;
	startupInfo.dwFillAttribute = 0;
	startupInfo.dwFlags = 0;
	startupInfo.wShowWindow = 0;
	startupInfo.cbReserved2 = 0;
	startupInfo.lpReserved2 = NULL;
	startupInfo.hStdInput = 0;
	startupInfo.hStdOutput = 0;
	startupInfo.hStdError = 0;

	return startupInfo;
}

bool injectModule(HANDLE processHandle, std::string const & modulePath)
{
	std::size_t stringSize = modulePath.length() + 1;

	LPVOID allocation = VirtualAllocEx(processHandle, 0, stringSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
	if(allocation == 0)
	{
		std::cout << "Failed to allocate memory for the library path: " << GetLastError() << std::endl;
		return false;
	}

	if(WriteProcessMemory(processHandle, allocation, modulePath.c_str(), stringSize, 0) == 0)
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
	HANDLE remoteThread = CreateRemoteThread(processHandle, 0, 0, reinterpret_cast<LPTHREAD_START_ROUTINE>(loadLibrary), allocation, 0, &threadId);
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

	CloseHandle(remoteThread);

	return true;
}

bool performSuspendedLaunchInjection(std::string const & executablePath, std::string const & workingDirectory, std::string const & modulePath, std::vector<std::string> const & arguments)
{
	STARTUPINFO startupInfo = emptyStartupInfo();
	PROCESS_INFORMATION processInformation;

	std::string commandLine = "\"" + executablePath + "\"";
	BOOST_FOREACH(std::string const & argument, arguments)
		commandLine += " \"" + argument + "\"";

	BOOL createProcessSuccess = CreateProcess(executablePath.c_str(), const_cast<LPSTR>(commandLine.c_str()), 0, 0, 0, CREATE_SUSPENDED, 0, workingDirectory.c_str(), &startupInfo, &processInformation);
	if(createProcessSuccess == 0)
	{
		std::cout << "Failed to create the process: " << GetLastError() << std::endl;
		return false;
	}

	bool injectionSuccessful = injectModule(processInformation.hProcess, modulePath);
	if(injectionSuccessful)
	{
		int resumeResult = ResumeThread(processInformation.hThread);
		if(resumeResult == -1)
		{
			std::cout << "Failed to resume main thread " << processInformation.hThread << " in the target process: " << GetLastError() << std::endl;
			return false;
		}
	}

	CloseHandle(processInformation.hProcess);
	CloseHandle(processInformation.hThread);

	return injectionSuccessful;
}

bool processSnapshot(PROCESSENTRY32 const & entry, std::string const & processBaseName, std::string const & modulePath)
{
	if(entry.szExeFile != processBaseName)
		return false;

	HANDLE processHandle = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION, FALSE, entry.th32ProcessID);
	if(processHandle == NULL)
	{
		std::cout << "Unable to open process (" << GetLastError() << ")" << std::endl;
		return false;
	}

	bool injectionSucceeded = injectModule(processHandle, modulePath);

	CloseHandle(processHandle);

	return injectionSucceeded;
}

bool injectIntoRunningProcess(std::string const & processBaseName, std::string const & modulePath)
{
	bool injectionSucceeded = false;
	PROCESSENTRY32 entry;
	entry.dwSize = static_cast<DWORD>(sizeof(PROCESSENTRY32));

	HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if(snapshot == INVALID_HANDLE_VALUE)
	{
		std::cout << "Unable to create snapshot" << std::endl;
		return false;
	}
	BOOL gotSnapshot = Process32First(snapshot, &entry);
	if(gotSnapshot == TRUE)
	{
		injectionSucceeded = processSnapshot(entry, processBaseName, modulePath);
		while(!injectionSucceeded)
		{
			gotSnapshot = Process32Next(snapshot, &entry);
			if(!gotSnapshot)
				break;
			injectionSucceeded = processSnapshot(entry, processBaseName, modulePath);
		}
	}
	if(!injectionSucceeded)
		std::cout << "Injection failed" << std::endl;
	CloseHandle(snapshot);
	return injectionSucceeded;
}

void printUsage(char * base)
{
	std::cout << "Usage:" << std::endl;
	std::cout << "To create a new process in suspended state and inject the DLL into it:" << std::endl;
	std::cout << base << " " << suspendedLaunchArgument << " <path to executable> <working directory> <path to DLL to inject> <arguments to pass to the executable>" << std::endl;
	std::cout << "To inject the DLL into a running process:" << std::endl;
	std::cout << base << " " << runningProcessArgument << " <base name of process executable> <path to DLL to inject>" << std::endl;
}

int main(int argc, char ** argv)
{
	if(argc == 6 && argv[1] == suspendedLaunchArgument)
	{
		std::string
			executablePath = argv[2],
			workingDirectory = argv[3],
			modulePath = argv[4];

		std::vector<std::string> arguments;
		for(int i = 4; i < argc; i++)
			arguments.push_back(argv[i]);

		std::cout << "Path to executable: " << executablePath << std::endl;
		std::cout << "Working directory: " << workingDirectory << std::endl;
		std::cout << "Path to the module to inject: " << modulePath << std::endl;

		if(!performSuspendedLaunchInjection(executablePath, workingDirectory, modulePath, arguments))
			return 1;
	}
	else if(argc == 4 && argv[1] == runningProcessArgument)
	{
		std::string
			processBaseName = argv[2],
			modulePath = argv[3];

		std::cout << "Process base name: " << processBaseName << std::endl;
		std::cout << "Path to the module to inject: " << modulePath << std::endl;

		if(!injectIntoRunningProcess(processBaseName, modulePath))
			return 1;
	}
	else
	{
		printUsage(argv[0]);
		return 1;
	}

	return 0;
}
