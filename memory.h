#pragma once
#include <stdio.h>
#include <Windows.h>
#include <TlHelp32.h>

DWORD pid = NULL;
HANDLE hProcess = NULL;
/******************************************************************/

int InitByWindowName(const wchar_t* windowname);
DWORD GetModuleAddr(const wchar_t* modulename);
int ReadMemory(DWORD addr, DWORD size, void* readbuff);
int WriteMemory(DWORD addr, DWORD size, void* writebuff);
int InjectShellcode(HANDLE hProcess, BYTE shellcode[]);
void ClearHandle(void);

/******************************************************************/

int InitByWindowName(const wchar_t* windowname)
{
	HWND hWnd = FindWindowW(NULL, windowname);
	GetWindowThreadProcessId(hWnd, &pid);
	printf("[+]pid is %08x\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	if (!hProcess)
	{
		printf("[!]get hProcess fail number: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

DWORD GetModuleAddr(const wchar_t* modulename)
{
	MODULEENTRY32 modentry;
	memset(&modentry, 0, sizeof(modentry));
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!hSnapshot)
	{
		printf("[!]create snapshot handle fail\n");
	}
	else
	{
		modentry.dwSize = sizeof(MODULEENTRY32);
		if (!Module32FirstW(hSnapshot, &modentry))
		{
			printf("[!]module32first fail\n");
		}
		else
		{
			do {
				//wprintf(L"%s\n", modentry.szModule);
				if (wcscmp(modentry.szModule, modulename) == 0)
				{
					CloseHandle(hSnapshot);
					return (DWORD)modentry.hModule;
					//DWORD result = *(DWORD*)&modentry.hModule;
					//return result;
				}
			} while (Module32Next(hSnapshot, &modentry));
		}
	}
	CloseHandle(hSnapshot);
	return FALSE;
}

int ReadMemory(DWORD addr, DWORD size, void* readbuff)
{
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	int result = ReadProcessMemory(hProcess, (void*)addr, readbuff, size, NULL);
	VirtualProtectEx(hProcess, (void*)addr, size, oldprotect, &oldprotect);
	return result;
}

int WriteMemory(DWORD addr, DWORD size, void* writebuff)
{
	DWORD oldprotect = NULL;
	VirtualProtectEx(hProcess, (void*)addr, size, PAGE_EXECUTE_READWRITE, &oldprotect);
	int result = WriteProcessMemory(hProcess, (void*)addr, writebuff, size, NULL);
	VirtualProtectEx(hProcess, (void*)addr, size, oldprotect, &oldprotect);
	return result;
}

int InjectShellcode(HANDLE hProcess, BYTE shellcode[])
{
	LPVOID calladdr = VirtualAllocEx(hProcess, NULL, 1024, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!calladdr)
	{
		printf("[!]VirtualAllocEx fail\n");
		return FALSE;
	}
	WriteProcessMemory(hProcess, calladdr, shellcode, 1024, NULL);
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, NULL, (DWORD(_stdcall*)(LPVOID))calladdr, NULL, NULL, NULL);
	if (!hRemote)
	{
		printf("[!]create remote thread fail\n");
		return FALSE;
	}
	WaitForSingleObject(hRemote, INFINITE);
	VirtualFreeEx(hProcess, calladdr, NULL, MEM_RELEASE);
	CloseHandle(hRemote);
	return TRUE;
}

void ClearHandle(void)
{
	CloseHandle(hProcess);
}
