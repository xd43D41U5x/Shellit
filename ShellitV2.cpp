/*
This is a basic shellcode launcher that is leveraging the ability of the Windows API function CallWindowProcA.
Whatever code is supplied in the memory region of the first parameter will be executed.
The other parameters can be used to pass arguments to the called shellcode. They will be available on the stack just like a normal call.

Example of passing params to CallWindowProcA.
ret = CallWindowProcA((WNDPROC)pShellcode, (HWND)pEncCode, std::uint32_t(fn), 0, 0);

In the sample this was written for, the address for ntprotecvirtualmemory was passed as a third parameter.
For items similar this is how you get that address:
HMODULE hMod = GetModuleHandleA("ntdll.dll");
void* fn = GetProcAddress(hMod, "NtProtectVirtualMemory");
std::cout << "[+] Found address for NTProtectVirtualMemory at: 0x" << std::hex << fn << std::endl;

This would then be passed to CallWindowProcA as noted above as the third param "fn".

The code above was added to this V2 version.
*/

#include <Windows.h>
#include <stdio.h>
#include <string>
#include <iostream>

int main()
{
	int ret = 0;
	int err = 0;
	DWORD shellSize = 0;
	std::string shellName;
	char anotherFile;
	char hold;

	printf("What is the name of the Shellcode file? ");
	std::cin >> shellName;

	printf("Do you need to enter another file as a parameter? (y/n) ");
	scanf_s(" %c", &anotherFile, 2);

	if (tolower(anotherFile) == 'y') {

		std::string paramFile;
		DWORD encSize = 0;

		printf("What is the name of the param file? ");
		std::cin >> paramFile;


		printf("[+] Opening Shellcode File: %s\n", shellName.c_str());
		printf("[+] Opening Ecrypted File: %s\n", paramFile.c_str());

		HANDLE shellFile = CreateFileA(shellName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		HANDLE encFile = CreateFileA(paramFile.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (shellFile == INVALID_HANDLE_VALUE)
		{
			err = GetLastError();
			printf("[-] ERROR: Unable to open Shell file. Error %i\n", err);
			return 0;
		}
		if (encFile == INVALID_HANDLE_VALUE)
		{
			err = GetLastError();
			printf("[-] ERROR: Unable to open Param file. Error %i\n", err);
			return 0;
		}

		shellSize = GetFileSize(shellFile, NULL);
		encSize = GetFileSize(encFile, NULL);

		if (shellSize == INVALID_FILE_SIZE)
		{
			err = GetLastError();
			printf("[-] ERROR: Shell file GetFileSize error %i\n", err);
			CloseHandle(shellFile);
			return 0;
		}
		if (encSize == INVALID_FILE_SIZE)
		{
			err = GetLastError();
			printf("[-] ERROR: Param File GetFileSize error %i\n", err);
			CloseHandle(encFile);
			return 0;
		}

		printf("[+] Shell File Size: %i bytes\n", shellSize);
		printf("[+] Param File Size: %i bytes\n", encSize);
		printf("[+] Allocating memory buffer...\n");

		void* pShellcode = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
		void* pEncCode = VirtualAlloc(NULL, encSize, MEM_COMMIT, PAGE_READWRITE);

		if (pShellcode == NULL)
		{
			err = GetLastError();
			printf("[-] ERROR: Shell File VirtualAlloc error %i\n", err);
			CloseHandle(shellFile);
			return 0;
		}
		if (pEncCode == NULL)
		{
			err = GetLastError();
			printf("[-] ERROR: Param File VirtualAlloc error %i\n", err);
			CloseHandle(encFile);
			return 0;
		}

		printf("[+] Reading files...\n");

		DWORD nShellBytesRead = 0;
		DWORD nEncBytesRead = 0;

		ReadFile(shellFile, pShellcode, shellSize, &nShellBytesRead, NULL);
		CloseHandle(shellFile);
		printf("[+] ShellCode file read completed with %i/%i bytes.\n", shellSize, nShellBytesRead);

		ReadFile(encFile, pEncCode, encSize, &nEncBytesRead, NULL);
		CloseHandle(encFile);
		printf("[+] Param file read completed with %i/%i bytes.\n", encSize, nEncBytesRead);

		HMODULE hMod = GetModuleHandleA("ntdll.dll");
		void* fn = GetProcAddress(hMod, "NtProtectVirtualMemory");
		std::cout << "[+] Found address for NTProtectVirtualMemory at: 0x" << std::hex << fn << std::endl;

		int fileloc1 = static_cast<int>(reinterpret_cast<intptr_t>(pShellcode));
		int fileloc2 = static_cast<int>(reinterpret_cast<intptr_t>(pEncCode));
		std::cout << "[+] ShellCode memory has been allocated (RWX) and code copied to: 0x" << std::hex << fileloc1 << std::endl;
		std::cout << "[+] Param memory has been allocated (RW) and code copied to: 0x" << std::hex << fileloc2 << std::endl;
		printf("[+] Pausing right before shell execution.  If needed, now would be the time to:\n");
		printf("   [+] Attach to this proess with x32dbg and set a bp on the shell memory region.\n");
		printf("   [+] Check allocted memory region contents with process hacker.\n");
		printf("[+] Enter any char and press enter to continue...\n");
		scanf_s(" %s", &hold, 2);


		printf("[+] Executing shellcode using CallWindowProc and passing param file as arg.\n");
		printf("[+] Hold on to your butts...\n");

		ret = CallWindowProcA((WNDPROC)pShellcode, (HWND)pEncCode, (UINT)fn, 0, 0);

		printf("[+] Shellcode executed!\n");
		return ret;

	}
	else {
		printf("[+] Opening Shellcode File: %s\n", shellName.c_str());

		HANDLE shellFile = CreateFileA(shellName.c_str(), GENERIC_READ, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

		if (shellFile == INVALID_HANDLE_VALUE)
		{
			err = GetLastError();
			printf("[-] ERROR: Unable to open file. Error %i\n", err);
			return 0;
		}

		shellSize = GetFileSize(shellFile, NULL);

		if (shellSize == INVALID_FILE_SIZE)
		{
			err = GetLastError();
			printf("[-] ERROR: GetFileSize error %i\n", err);
			CloseHandle(shellFile);
			return 0;
		}

		printf("[+] Shell File Size: %i bytes\n", shellSize);
		printf("[+] Allocating memory buffer...\n");

		void* pShellcode = VirtualAlloc(NULL, shellSize, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

		if (pShellcode == NULL)
		{
			err = GetLastError();
			printf("[-] ERROR: VirtualAlloc error %i\n", err);
			CloseHandle(shellFile);
			return 0;
		}

		printf("[+] Reading file...\n");

		DWORD nShellBytesRead = 0;

		ReadFile(shellFile, pShellcode, shellSize, &nShellBytesRead, NULL);
		CloseHandle(shellFile);
		printf("[+] ShellCode file read completed with %i/%i bytes.\n", shellSize, nShellBytesRead);

		int fileloc1 = static_cast<int>(reinterpret_cast<intptr_t>(pShellcode));
		std::cout << "[+] ShellCode memory has been allocated (RWX) and code copied to: 0x" << std::hex << fileloc1 << std::endl;
		printf("[+] Pausing right before shell execution.  If needed, now would be the time to:\n");
		printf("   [+] Attach to this proess with x32dbg and set a bp on the shell memory region.\n");
		printf("   [+] Check allocted memory region contents with process hacker.\n");
		printf("[+] Enter any char and press enter to continue...\n");
		scanf_s(" %s", &hold, 2);


		printf("[+] Executing shellcode using CallWindowProc...\n");
		printf("[+] Hold on to your butts...\n");

		ret = CallWindowProcA((WNDPROC)pShellcode, 0, 0, 0, 0);

		printf("[+] Shellcode executed!\n");
		return ret;
	}
}
