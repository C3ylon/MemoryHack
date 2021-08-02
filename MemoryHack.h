#pragma once
#include <stdio.h>

#include <Windows.h>
#include <TlHelp32.h>


DWORD pid = NULL;
HANDLE hProcess = NULL;

int InitByPid(DWORD pid)
{
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	printf("[+]hProcess is %08x\n", hProcess);
	if (!hProcess)
	{
		printf("[!]get hProcess fail number: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

int InitByWindowName(const wchar_t* windowname)
{
	HWND hWnd = FindWindowW(NULL, windowname);
	GetWindowThreadProcessId(hWnd, &pid);
	printf("[+]pid is %08x\n", pid);
	hProcess = OpenProcess(PROCESS_ALL_ACCESS, NULL, pid);
	printf("[+]hProcess is %08x\n", hProcess);
	if (!hProcess)
	{
		printf("[!]get hProcess fail number: %d\n", GetLastError());
		return FALSE;
	}
	return TRUE;
}

DWORD GetModuleAddr(DWORD pid, CONST WCHAR* modname)
{

	MODULEENTRY32W moduleEntry;
	memset(&moduleEntry, 0, sizeof(MODULEENTRY32W));
	HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pid);
	if (!hSnapshot)
	{
		printf("[!]create snapshot handle fail\n");
		CloseHandle(hSnapshot);
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
			DWORD result = *(DWORD*)&moduleEntry.hModule;
			wprintf(L"[+]\"%s\" module address is %08x\n", modname, result);
			CloseHandle(hSnapshot);
			return result;
		}
	} while (Module32NextW(hSnapshot, &moduleEntry));
	printf("[!]don't find such module\n");
	CloseHandle(hSnapshot);
	return NULL;
}

int EnableDebugPriv()
{
	HANDLE hToken;        //�������ƾ��
	TOKEN_PRIVILEGES tp;  //TOKEN_PRIVILEGES�ṹ�壬���а���һ��������+��������Ȩ������
	LUID luid;           //�����ṹ���е�����ֵ
	//�򿪽������ƻ�
	//GetCurrentProcess()��ȡ��ǰ���̵�α�����ֻ��ָ��ǰ���̻����߳̾������ʱ�仯
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
	{
		printf("[!]OpenProcessToken error\n");
		return FALSE;
	}
	//��ñ��ؽ���name�������Ȩ�����͵ľֲ�ΨһID
	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid))
	{
		printf("[!]LookupPrivilegeValue error\n");
		return FALSE;
	}
	tp.PrivilegeCount = 1;                               //Ȩ��������ֻ��һ����Ԫ�ء�
	tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;  //Ȩ�޲���
	tp.Privileges[0].Luid = luid;                        //Ȩ������
	//��������Ȩ��
	if (!AdjustTokenPrivileges(hToken, 0, &tp, sizeof(TOKEN_PRIVILEGES), NULL, NULL))
	{
		printf("[!]AdjustTokenPrivileges error!\n");
		return FALSE;
	}
	return TRUE;
}

int InjectShellcode(BYTE shellcode[])
{
	EnableDebugPriv();
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
	HANDLE hRemote = CreateRemoteThread(hProcess, NULL, NULL, (DWORD(_stdcall*)(LPVOID))calladdr, NULL, NULL, NULL);
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


