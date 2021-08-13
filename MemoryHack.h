#pragma once
#include <stdio.h>

#include <Windows.h>
#include <TlHelp32.h>

typedef UINT64 QWORD;

DWORD pid = NULL;
HANDLE hProcess = NULL;

int EnableDebugPriv()
{
	HANDLE hToken = NULL;
	TOKEN_PRIVILEGES tp;
	LUID luid;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("[!]OpenProcessToken error\n");
		return FALSE;
	}
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return FALSE;
	}
	tp.PrivilegeCount = 1;
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
	tp.Privileges[0].Luid = luid;
	if (!AdjustTokenPrivileges(hToken, NULL, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]AdjustTokenPrivileges error!\n");
		return FALSE;
	}
	printf("[+]Enable debug privileges success\n");
	return TRUE;
}

typedef NTSTATUS(NTAPI* LPFN_NTWOW64READVIRTUALMEMORY64)(
	IN  HANDLE   ProcessHandle,
	IN  ULONG64  BaseAddress,
	OUT PVOID    BufferData,
	IN  ULONG64  BufferLength,
	OUT PULONG64 ReturnLength OPTIONAL);
typedef NTSTATUS(NTAPI* LPFN_NTWOW64WRITEVIRTUALMEMORY64)(
	IN  HANDLE   ProcessHandle,
	IN  ULONG64  BaseAddress,
	OUT PVOID    BufferData,
	IN  ULONG64  BufferLength,
	OUT PULONG64 ReturnLength OPTIONAL);
LPFN_NTWOW64READVIRTUALMEMORY64       __NtWow64ReadVirtualMemory64;
LPFN_NTWOW64WRITEVIRTUALMEMORY64	  __NtWow64WriteVirtualMemory64;
int GetNtWow64MemoryProcAddr()
{
	HMODULE NtdllModuleBase = NULL;
	NtdllModuleBase = GetModuleHandle(L"Ntdll.dll");
	if (!NtdllModuleBase)
	{
		printf("[!]get ntdll address fail\n");
		return FALSE;
	}
	__NtWow64ReadVirtualMemory64 = (LPFN_NTWOW64READVIRTUALMEMORY64)GetProcAddress(NtdllModuleBase, "NtWow64ReadVirtualMemory64");
	__NtWow64WriteVirtualMemory64 = (LPFN_NTWOW64WRITEVIRTUALMEMORY64)GetProcAddress(NtdllModuleBase, "NtWow64WriteVirtualMemory64");
	if (!(__NtWow64ReadVirtualMemory64 && __NtWow64WriteVirtualMemory64))
	{
		printf("[!]get nt64 read|write proc address fail\n");
		return FALSE;
	}
	return	 TRUE;
}

int InitByPid(DWORD ProcessID)
{
	pid = ProcessID;
	EnableDebugPriv();
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	printf("[+]hProcess is %08x\n", (DWORD)hProcess);
	if (!hProcess)
	{
		printf("[!]get hProcess fail number: %d\n", GetLastError());
		return FALSE;
	} 
#ifndef _WIN64
	if (GetNtWow64MemoryProcAddr()) return TRUE;
	else return FALSE;
#endif
	return TRUE;
}

int InitByWindowName(const wchar_t* windowname)
{
	EnableDebugPriv();
	HWND hWnd = FindWindowW(NULL, windowname);
	GetWindowThreadProcessId(hWnd, &pid);
	if (!pid)
	{
		wprintf(L"[!]don't find \"%s\" pid\n", windowname);
		return FALSE;
	}
	printf("[+]pid is %08x\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		printf("[!]get hProcess fail number: %d\n", GetLastError());
		return FALSE;
	}
	printf("[+]hProcess is %p\n", hProcess);
#ifndef _WIN64
	if (GetNtWow64MemoryProcAddr()) return TRUE;
	else return FALSE;
#endif
	return TRUE;
}

SIZE_T GetModuleAddr(CONST WCHAR* modname)
{
	MODULEENTRY32W moduleEntry;
	memset(&moduleEntry, 0, sizeof(MODULEENTRY32W));
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!hSnapshot)
	{
		printf("[!]create snapshot handle fail\n");
		return FALSE;
	}
	moduleEntry.dwSize = sizeof(MODULEENTRY32W);
	if (!Module32FirstW(hSnapshot, &moduleEntry))
	{
		printf("[!]module32first fail\n");
		CloseHandle(hSnapshot);
		return FALSE;
	}
	do {
		if (wcscmp(moduleEntry.szModule, modname) == 0)
		{
			SIZE_T result = *(SIZE_T*)&moduleEntry.hModule;
			wprintf(L"[+]\"%s\" module address is %p\n", modname, result);
			CloseHandle(hSnapshot);
			return result;
		}
	} while (Module32NextW(hSnapshot, &moduleEntry));
	printf("[!]don't find such module\n");
	CloseHandle(hSnapshot);
	return NULL;
}

int InjectShellcode(BYTE shellcode[])
{
	LPVOID calladdr = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!calladdr)
	{
		printf("[!]VirtualAllocEx fail\n");
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, calladdr, shellcode, 1024, NULL))
	{
		printf("[!]write shellcode in target process fail\n");
		VirtualFreeEx(hProcess, calladdr, NULL, MEM_RELEASE);
		return FALSE;
	}
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)calladdr, NULL, NULL, NULL);
	if (!hRemote)
	{
		printf("[!]create remote thread fail\n");
		VirtualFreeEx(hProcess, calladdr, NULL, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hRemote, INFINITE);
	VirtualFreeEx(hProcess, calladdr, NULL, MEM_RELEASE);
	CloseHandle(hRemote);
	return TRUE;
}

int InjectDll(BYTE dllpayload[4096])
{
	LPVOID dllAddr = VirtualAllocEx(hProcess, NULL, 4096, MEM_COMMIT, PAGE_READWRITE);
	if (!dllAddr)
	{
		printf("[!]VirtualAllocEx fail\n");
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, dllAddr, dllpayload, 4096, NULL))
	{
		printf("[!]write dll payload in target process fail\n");
		VirtualFreeEx(hProcess, dllAddr, NULL, MEM_RELEASE);
		return FALSE;
	}
	HMODULE kerneldlladdr = GetModuleHandleW(L"Kernel32.dll");
	LPVOID pLoadLibraryA = GetProcAddress(kerneldlladdr, "LoadLibraryA");
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pLoadLibraryA, dllAddr, NULL, NULL);
	if (!hRemote)
	{
		printf("[!]create remote thread fail\n");
		VirtualFreeEx(hProcess, dllAddr, NULL, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hRemote, INFINITE);
	VirtualFreeEx(hProcess, dllAddr, NULL, MEM_RELEASE);
	CloseHandle(hRemote);
	return TRUE;
}

int UnloadDll(char dllname[256])
{
	DWORD threadresult = NULL;
	LPVOID dllnamebuffer = VirtualAllocEx(hProcess, NULL, 256, MEM_COMMIT, PAGE_READWRITE);
	if (!dllnamebuffer)
	{
		printf("[!]VirtualAllocEx fail\n");
		return FALSE;
	}
	if (!WriteProcessMemory(hProcess, dllnamebuffer, dllname, 256, NULL))
	{
		printf("[!]write dll path in target process fail\n");
		VirtualFreeEx(hProcess, dllnamebuffer, NULL, MEM_RELEASE);
		return FALSE;
	}
	LPVOID pFunc = GetProcAddress(GetModuleHandle(L"Kernel32"), "GetModuleHandleA");
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pFunc, dllnamebuffer, NULL, NULL);
	if (!hRemote)
	{
		printf("[!]create remote thread fail\n");
		VirtualFreeEx(hProcess, dllnamebuffer, NULL, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hRemote, INFINITE);
	GetExitCodeThread(hRemote, &threadresult);
	CloseHandle(hRemote);
	pFunc = GetProcAddress(GetModuleHandle(L"Kernel32"), "FreeLibraryAndExitThread");
	hRemote = CreateRemoteThread(hProcess, NULL, NULL, (LPTHREAD_START_ROUTINE)pFunc, (LPVOID)threadresult, NULL, NULL);
	if (!hRemote)
	{
		printf("[!]create remote thread fail\n");
		VirtualFreeEx(hProcess, dllnamebuffer, NULL, MEM_RELEASE);
		return FALSE;
	}
	WaitForSingleObject(hRemote, INFINITE);
	CloseHandle(hRemote);
	VirtualFreeEx(hProcess, dllnamebuffer, NULL, MEM_RELEASE);
	return TRUE;
}

int ReadMemory(SIZE_T addr, SIZE_T size, void* readbuff)
{
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	int result = ReadProcessMemory(hProcess, (void*)addr, readbuff, size, NULL);
	VirtualProtectEx(hProcess, (void*)addr, size, oldprotect, &oldprotect);
	return result;
}

int WriteMemory(SIZE_T addr, SIZE_T size, void* writebuff)
{
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	int result = WriteProcessMemory(hProcess, (void*)addr, writebuff, size, NULL);
	VirtualProtectEx(hProcess, (void*)addr, size, oldprotect, &oldprotect);
	return result;
}

void ClearHandle(void)
{
	CloseHandle(hProcess);
	printf("[+]finish memory hack\n");
}

int Rint(QWORD addr)
{
	int buff = 0;
	NTSTATUS Status = __NtWow64ReadVirtualMemory64(hProcess, addr, &buff, 4, NULL);
	return buff;
}

float Rfloat(QWORD addr)
{
	float buff = 0;
	NTSTATUS Status = __NtWow64ReadVirtualMemory64(hProcess, addr, &buff, 4, NULL);
	return buff;
}

double Rdouble(QWORD addr)
{
	double buff = 0;
	NTSTATUS Status = __NtWow64ReadVirtualMemory64(hProcess, addr, &buff, 8, NULL);
	return buff;
}

void Wint(QWORD addr, int val)
{
	int _val = val;
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldprotect);
	NTSTATUS Status = __NtWow64WriteVirtualMemory64(hProcess, addr, &_val, 4, NULL);
	VirtualProtectEx(hProcess, (void*)addr, 4, oldprotect, &oldprotect);
}

void Wfloat(QWORD addr, float val)
{
	float _val = val;
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, 4, PAGE_EXECUTE_READWRITE, &oldprotect);
	NTSTATUS Status = __NtWow64WriteVirtualMemory64(hProcess, addr, &_val, 4, NULL);
	VirtualProtectEx(hProcess, (void*)addr, 4, oldprotect, &oldprotect);
}

void Wdouble(QWORD addr, double val)
{
	double _val = val;
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, 8, PAGE_EXECUTE_READWRITE, &oldprotect);
	NTSTATUS Status = __NtWow64WriteVirtualMemory64(hProcess, addr, &_val, 8, NULL);
	VirtualProtectEx(hProcess, (void*)addr, 8, oldprotect, &oldprotect);
}

