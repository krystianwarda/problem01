#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

bool InjectDLL(const char* dllPath, const char* processSubstring)
{
    DWORD processId = 0;
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE)
        return false;

    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (!Process32First(hSnapshot, &pe32))
    {
        CloseHandle(hSnapshot);
        return false;
    }

    do
    {
        if (strstr(pe32.szExeFile, processSubstring))
        {
            processId = pe32.th32ProcessID;
            break;
        }
    } while (Process32Next(hSnapshot, &pe32));
    CloseHandle(hSnapshot);

    if (!processId)
    {
        std::cout << "Target process not found!" << std::endl;
        return false;
    }

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | 
                                  PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, 
                                  FALSE, processId);
    if (!hProcess)
    {
        std::cout << "Failed to open target process!" << std::endl;
        return false;
    }

    void* pDllPath = VirtualAllocEx(hProcess, 0, strlen(dllPath) + 1, MEM_COMMIT, PAGE_READWRITE);
    if (!pDllPath)
    {
        CloseHandle(hProcess);
        std::cout << "Failed to allocate memory in target process!" << std::endl;
        return false;
    }

    if (!WriteProcessMemory(hProcess, pDllPath, dllPath, strlen(dllPath) + 1, NULL))
    {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cout << "Failed to write to target process memory!" << std::endl;
        return false;
    }

    HANDLE hThread = CreateRemoteThread(hProcess, 0, 0, 
                                       (LPTHREAD_START_ROUTINE)GetProcAddress(GetModuleHandleA("Kernel32.dll"), 
                                       "LoadLibraryA"), pDllPath, 0, 0);
    if (!hThread)
    {
        VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        std::cout << "Failed to create remote thread in target process!" << std::endl;
        return false;
    }

    CloseHandle(hThread);
    VirtualFreeEx(hProcess, pDllPath, 0, MEM_RELEASE);
    CloseHandle(hProcess);
    return true;
}

int main()
{
    const char* dllPath = "C:\\Projects\\CPP\\libHelloWorld2.dll";
    if (InjectDLL(dllPath, "eale"))
        std::cout << "DLL Injected successfully!" << std::endl;
    else
        std::cout << "DLL Injection failed!" << std::endl;

    return 0;
}
