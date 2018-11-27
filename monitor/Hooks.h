#include <cstdio>
#include <Windows.h>
#include <iostream>
#include "MinHook.h"
#include <intrin.h>
#include <winternl.h>

#pragma comment(lib, "libMinHook-x64-v141-mtd.lib")
#include <vector>

void* ignoreAddresses[] = {
	reinterpret_cast<void*>(0x000000014506CD7C), 
	reinterpret_cast<void*>(0x000000014A678C8C), 
	reinterpret_cast<void*>(0x000000014506C68E),
	reinterpret_cast<void*>(0x00000001403EE883)};

typedef void (WINAPI *OPENPROCESS)(DWORD, BOOL, DWORD);
OPENPROCESS oOpenProcess = nullptr;

void hkOpenProcess(DWORD dwDesiredAccess, BOOL bInheritHandle, DWORD dwProcessId) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "OpenProcess\t" << "\tdwDesiredAccess\t" << dwDesiredAccess << "\tbInheritHandle\t" << bInheritHandle << "\tdwProcessId\t" << dwProcessId << std::endl;
	return oOpenProcess(dwDesiredAccess, bInheritHandle, dwProcessId);
}

typedef void (WINAPI *LOADLIBRARYA)(LPCSTR);
LOADLIBRARYA oLoadLibraryA = nullptr;

void hkLoadLibraryA(LPCSTR lpLibFileName) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tLoadLibraryA" << "\tlpLibFileName:\t" << lpLibFileName << std::endl;
	return oLoadLibraryA(lpLibFileName);
}

typedef void (WINAPI *NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
NTREADVIRTUALMEMORY oNtReadVirtualMemory = nullptr;

void hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tNtReadVirtualMemory" << "\tProcessHandle:\t" << ProcessHandle << "\tBaseAddress:\t" << BaseAddress << "\tBuffer:\t" << Buffer << "\tNumberOfBytesToRead:\t" << NumberOfBytesToRead << "\tNumberOfBytesReaded:\t" << NumberOfBytesReaded << std::endl;
	return oNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, NumberOfBytesToRead, NumberOfBytesReaded);
}

typedef void (WINAPI *WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WRITEPROCESSMEMORY oWriteProcessMemory = nullptr;

void hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "WriteProcessMemory\t" << "\thProcess\t" << hProcess << "\tlpBaseAddress\t" << lpBaseAddress << "\tlpBuffer\t" << lpBuffer << "\tnSize\t" << nSize << "\tlpNumberOfBytesWritten\t" << lpNumberOfBytesWritten << std::endl;
	return oWriteProcessMemory(hProcess, lpBaseAddress, lpBuffer, nSize, lpNumberOfBytesWritten);
}

typedef void (WINAPI *VIRTUALQUERY)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
VIRTUALQUERY oVirtualQuery = nullptr;

void hkVirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tVirtualQuery" << "\tlpAddress:\t" << lpAddress << "\tlpBuffer:\t" << lpBuffer << "\tdwLength:\t" << dwLength << std::endl;
	return oVirtualQuery(lpAddress, lpBuffer, dwLength);
}


typedef void (WINAPI *VIRTUALQUERYEX)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
VIRTUALQUERYEX oVirtualQueryEx = nullptr;

void hkVirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "VirtualQueryEx\t" << "\thProcess:\t" << hProcess << "\tlpAddress:\t" << lpAddress << "\tlpBuffer:\t" << lpBuffer << "\tdwLength:\t" << dwLength << std::endl;	return oVirtualQueryEx(hProcess, lpAddress, lpBuffer, dwLength);
}


typedef void (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
VIRTUALALLOC oVirtualAlloc = nullptr;

void hkVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tVirtualAlloc" << "\tlpAddress:\t" << lpAddress << "\tdwSize:\t" << dwSize << "\tflAllocationType:\t" << flAllocationType << "\tflProtect:\t" << flProtect << std::endl;
	return oVirtualAlloc(lpAddress, dwSize, flAllocationType, flProtect);
}

typedef void (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
VIRTUALALLOCEX oVirtualAllocEx = nullptr;

void hkVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tVirtualAllocEx" << "\thProcess:\t" << hProcess << "\tlpAddress:\t" << lpAddress << "\tdwSize:\t" << dwSize << "\tflAllocationType:\t" << flAllocationType << "\tflProtect:\t" << flProtect << std::endl;
	return oVirtualAllocEx(hProcess, lpAddress, dwSize, flAllocationType, flProtect);
}

typedef void (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
VIRTUALFREE oVirtualFree = nullptr;

void hkVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tVirtualFree" << "\tlpAddress:\t" << lpAddress << "\tdwSize:\t" << dwSize << "\tdwFreeType:\t" << dwFreeType << std::endl;
	return oVirtualFree(lpAddress, dwSize, dwFreeType);
}


typedef void (WINAPI *NTCREATESECTION)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTCREATESECTION oNtCreateSection = nullptr;

void hkNtCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tNtCreateSection" << "\tSectionHandle:\t" << SectionHandle << "\tDesiredAccess:\t" << DesiredAccess << "\tObjectAttributes:\t" << ObjectAttributes << "\tMaximumSize:\t" << MaximumSize << "\tPageAttributess:\t" << PageAttributess << "\tSectionAttributes:\t" << SectionAttributes << "\tFileHandle:\t" << FileHandle << std::endl;
	return oNtCreateSection(SectionHandle, DesiredAccess, ObjectAttributes, MaximumSize, PageAttributess, SectionAttributes, FileHandle);
}

typedef void (WINAPI *NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
NTCREATEPROCESS oNtCreateProcess = nullptr;

void hkNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tNtCreateProcess" << "\tProcessHandle:\t" << ProcessHandle << "\tDesiredAccess:\t" << DesiredAccess << "\tObjectAttributes:\t" << ObjectAttributes << "\tParentProcess:\t" << ParentProcess << "\tInheritObjectTable:\t" << InheritObjectTable << "\tSectionHandle:\t" << SectionHandle << "\tDebugPort:\t" << DebugPort << "\tExceptionPort:\t" << ExceptionPort << std::endl;
	return oNtCreateProcess(ProcessHandle, DesiredAccess, ObjectAttributes, ParentProcess, InheritObjectTable, SectionHandle, DebugPort, ExceptionPort);
}

typedef void (WINAPI *DECODEPOINTER)(PVOID);
DECODEPOINTER oDecodePointer = nullptr;

void hkDecodePointer(PVOID Ptr) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tDecodePointer" << "\tPtr:\t" << Ptr << std::endl;
	return oDecodePointer(Ptr);
}

typedef void (WINAPI *ENCODEPOINTER)(PVOID);
ENCODEPOINTER oEncodePointer = nullptr;

void hkEncodePointer(PVOID Ptr) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))	std::cout << std::hex << "0x" << _ReturnAddress() << "\tEncodePointer" << "\tPtr:\t" << Ptr << std::endl;
	return oEncodePointer(Ptr);
}