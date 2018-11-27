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
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *LOADLIBRARYA)(LPCSTR);
LOADLIBRARYA oLoadLibraryA = nullptr;

void hkLoadLibraryA(LPCSTR lpLibFileName) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *NTREADVIRTUALMEMORY)(HANDLE, PVOID, PVOID, ULONG, PULONG);
NTREADVIRTUALMEMORY oNtReadVirtualMemory = nullptr;

void hkNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, ULONG NumberOfBytesToRead, PULONG NumberOfBytesReaded) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *WRITEPROCESSMEMORY)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
WRITEPROCESSMEMORY oWriteProcessMemory = nullptr;

void hkWriteProcessMemory(HANDLE hProcess, LPVOID lpBaseAddress, LPCVOID lpBuffer, SIZE_T nSize, SIZE_T* lpNumberOfBytesWritten) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *VIRTUALQUERY)(LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
VIRTUALQUERY oVirtualQuery = nullptr;

void hkVirtualQuery(LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}


typedef void (WINAPI *VIRTUALQUERYEX)(HANDLE, LPCVOID, PMEMORY_BASIC_INFORMATION, SIZE_T);
VIRTUALQUERYEX oVirtualQueryEx = nullptr;

void hkVirtualQueryEx(HANDLE hProcess, LPCVOID lpAddress, PMEMORY_BASIC_INFORMATION lpBuffer, SIZE_T dwLength) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))
}


typedef void (WINAPI *VIRTUALALLOC)(LPVOID, SIZE_T, DWORD, DWORD);
VIRTUALALLOC oVirtualAlloc = nullptr;

void hkVirtualAlloc(LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *VIRTUALALLOCEX)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
VIRTUALALLOCEX oVirtualAllocEx = nullptr;

void hkVirtualAllocEx(HANDLE hProcess, LPVOID lpAddress, SIZE_T dwSize, DWORD flAllocationType, DWORD flProtect) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *VIRTUALFREE)(LPVOID, SIZE_T, DWORD);
VIRTUALFREE oVirtualFree = nullptr;

void hkVirtualFree(LPVOID lpAddress, SIZE_T dwSize, DWORD dwFreeType) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}


typedef void (WINAPI *NTCREATESECTION)(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
NTCREATESECTION oNtCreateSection = nullptr;

void hkNtCreateSection(PHANDLE SectionHandle, ULONG DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, PLARGE_INTEGER MaximumSize, ULONG PageAttributess, ULONG SectionAttributes, HANDLE FileHandle) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *NTCREATEPROCESS)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);
NTCREATEPROCESS oNtCreateProcess = nullptr;

void hkNtCreateProcess(PHANDLE ProcessHandle, ACCESS_MASK DesiredAccess, POBJECT_ATTRIBUTES ObjectAttributes, HANDLE ParentProcess, BOOLEAN InheritObjectTable, HANDLE SectionHandle, HANDLE DebugPort, HANDLE ExceptionPort) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *DECODEPOINTER)(PVOID);
DECODEPOINTER oDecodePointer = nullptr;

void hkDecodePointer(PVOID Ptr) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}

typedef void (WINAPI *ENCODEPOINTER)(PVOID);
ENCODEPOINTER oEncodePointer = nullptr;

void hkEncodePointer(PVOID Ptr) {
	if (std::find(std::begin(ignoreAddresses), std::end(ignoreAddresses), _ReturnAddress()) == std::end(ignoreAddresses))

}