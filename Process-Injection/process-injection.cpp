#include <Windows.h>
#include <string>
#include <memory>
#include <tlhelp32.h>
#include <filesystem>

int wmain(int argc, wchar_t* argv[]) {
	// left purposefully blank so this can't be used off the shelf
}

// enable debug privs of current process
int EnableDebugPrivs() {
	HANDLE hToken = NULL;
	LUID luid;
	TOKEN_PRIVILEGES tkp;
	std::unique_ptr<void, decltype(&CloseHandle)> uphToken(static_cast<void*>(hToken), CloseHandle);

	// populate handle to current process' token
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		return 1; // unable to get handle to token
	}

	// find the value of SeDebugPrivilege so we can enable it
	if (!LookupPrivilegeValueW(NULL, L"SeDebugPrivilege", &luid)) {
		return 2; // unable to find that privilege
	}

	// populate the token privileges struct to enable debug privs
	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = luid;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	// apply changes
	if (!AdjustTokenPrivileges(hToken, false, &tkp, sizeof(tkp), NULL, NULL)) {
		return 3; // applying changes failed
	}

	return 0;
}

int ProcessInjection(DWORD targetPID, std::wstring dllPath) {
	MODULEENTRY32W me;
	me.dwSize = sizeof(MODULEENTRY32W);
	HMODULE hKernel32 = NULL;
	BOOL foundKernel32 = FALSE;
	LPTHREAD_START_ROUTINE pLoadLibrary = NULL;
	HANDLE hTargetProcess = NULL;
	PVOID baseInjMemAddr;
	HANDLE hInjectedThread = NULL;
	std::unique_ptr<void, decltype(&CloseHandle)> uphKernel32(static_cast<void*>(hKernel32), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphTargetProcess(static_cast<void*>(hTargetProcess), CloseHandle);
	std::unique_ptr<void, decltype(&CloseHandle)> uphInjectedThread(static_cast<void*>(hInjectedThread), CloseHandle);

    // check that the dll to inject exists
    std::filesystem::path fsDLLPath = dllPath;
    if (!std::filesystem::exists(fsDLLPath)) {
        return 1;
    }

    // get list of modules within target process
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, targetPID);
    std::unique_ptr<void, decltype(&CloseHandle)> uphSnapshot(static_cast<void*>(hSnapshot), CloseHandle);
    if (hSnapshot == INVALID_HANDLE_VALUE || !Module32FirstW(hSnapshot, &me)) {
        return 2; // list of processes is invalid or empty
    }

    // find KERNEL32.DLL
    do {
        if (me.szModule.compare(L"KERNEL32.DLL") == 0) {
            hKernel32 = me.hModule;
            foundKernel32 = TRUE;
        }
    } while (Module32NextW(hSnapshot, &me) && !foundKernel32);

    if (!foundKernel32) {
        return 3; // unable to find KERNEL32.DLL
    }

    // get a pointer to LoadLibraryW from KERNEL32.DLL
    pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(hKernel32, "LoadLibraryW");
    if (pLoadLibrary == NULL) {
        return 4; // unable to get LoadLibraryW pointer
    }

    // get handle to target process
    DWORD dwDesiredAccess = PROCESS_QUERY_INFORMATION | PROCESS_CREATE_THREAD | PROCESS_VM_OPERATION | PROCESS_VM_WRITE;
    hTargetProcess = OpenProcess(dwDesiredAccess, FALSE, targetPID);
    if (hTargetProcess == NULL || hTargetProcess == INVALID_HANDLE_VALUE) {
        return 5; // handle to target process is invalid or null
    }

    // allocate memory inside target process
    DWORD dwAllocateSize = (dllPath.length() + 1) * 2;
    baseInjMemAddr = VirtualAllocEx(hTargetProcess, NULL, dwAllocateSize, MEM_COMMIT, PAGE_READWRITE);
    if (baseInjMemAddr == NULL) {
        return 6; // allocation failed
    }

    // write dll path inside target process
    if (!WriteProcessMemory(hTargetProcess, baseInjMemAddr, (LPVOID)dllPath.c_str(), dwAllocateSize, NULL)) {
        return 7; // write failed
    }

    // instruct target to create a new thread and use LoadLibraryW to load our dll
    hInjectedThread = CreateRemoteThread(hTargetProcess, NULL, 0, pLoadLibrary, baseInjMemAddr, 0, NULL);
    if (hInjectedThread == NULL || hInjectedThread == INVALID_HANDLE_VALUE) {
        return 8; // create thread failed
    }

    return 0;
}