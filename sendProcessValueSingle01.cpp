#include <Windows.h>
#include <iostream>

void InjectedFunction() {
    typedef void (__fastcall* _TargetFunc)(const char*); // Only a string argument now
    _TargetFunc targetFunction = (_TargetFunc)0x00344950;

    targetFunction("HelloC"); // Calling the function with a single string argument
}

int main() {
    DWORD pid = 7184; // Target process ID
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (hProcess == NULL) {
        std::cout << "Could not open the process. Error code: " << GetLastError() << std::endl;
        return 1;
    }

    LPVOID pCode = VirtualAllocEx(hProcess, 0, 4096, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (!pCode) {
        std::cout << "Memory allocation failed. Error code: " << GetLastError() << std::endl;
        CloseHandle(hProcess);
        return 1;
    }

    if (!WriteProcessMemory(hProcess, pCode, (LPVOID)InjectedFunction, 4096, 0)) {
        std::cout << "Failed to write to the target process memory. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, (LPTHREAD_START_ROUTINE)pCode, 0, 0, 0);
    if (!hThread) {
        std::cout << "Remote thread creation failed. Error code: " << GetLastError() << std::endl;
        VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pCode, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return 0;
}
