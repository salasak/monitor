#include "Hooks.h"
#include <Windows.h>
//#include "proxydll.h"
#include <Shlwapi.h>
#include <winternl.h>

#pragma comment(lib,"ntdll.lib")
EXTERN_C NTSTATUS NTAPI NtReadVirtualMemory(HANDLE, PVOID, PVOID, ULONG, PULONG);
EXTERN_C NTSTATUS NTAPI NtCreateSection(PHANDLE, ULONG, POBJECT_ATTRIBUTES, PLARGE_INTEGER, ULONG, ULONG, HANDLE);
EXTERN_C NTSTATUS NTAPI NtCreateProcess(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, BOOLEAN, HANDLE, HANDLE, HANDLE);

DWORD WINAPI Looper(LPVOID lpParam)
{
	MH_Initialize();
	MH_CreateHook(&NtReadVirtualMemory, &hkNtReadVirtualMemory, reinterpret_cast<LPVOID*>(&oNtReadVirtualMemory));
	MH_EnableHook(&NtReadVirtualMemory);
	MH_CreateHook(&OpenProcess, &hkOpenProcess, reinterpret_cast<LPVOID*>(&oOpenProcess));
	MH_EnableHook(&OpenProcess);
	MH_CreateHook(&LoadLibraryA, &hkLoadLibraryA, reinterpret_cast<LPVOID*>(&oLoadLibraryA));
	MH_EnableHook(&LoadLibraryA);
	MH_CreateHook(&WriteProcessMemory, &hkWriteProcessMemory, reinterpret_cast<LPVOID*>(&oWriteProcessMemory));
	MH_EnableHook(&WriteProcessMemory);
	MH_CreateHook(&VirtualQuery, &hkVirtualQuery, reinterpret_cast<LPVOID*>(&oVirtualQuery));
	MH_EnableHook(&VirtualQuery);
	MH_CreateHook(&VirtualQueryEx, &hkVirtualQueryEx, reinterpret_cast<LPVOID*>(&oVirtualQueryEx));
	MH_EnableHook(&VirtualQueryEx);
	MH_CreateHook(&VirtualAlloc, &hkVirtualAlloc, reinterpret_cast<LPVOID*>(&oVirtualAlloc));
	MH_EnableHook(&VirtualAlloc);
	MH_CreateHook(&VirtualAllocEx, &hkVirtualAllocEx, reinterpret_cast<LPVOID*>(&oVirtualAllocEx));
	MH_EnableHook(&VirtualAllocEx);
	MH_CreateHook(&VirtualFree, &hkVirtualFree, reinterpret_cast<LPVOID*>(&oVirtualFree));
	MH_EnableHook(&VirtualFree);
	MH_CreateHook(&NtCreateSection, &hkNtCreateSection, reinterpret_cast<LPVOID*>(&oNtCreateSection));
	MH_EnableHook(&NtCreateSection);
	MH_CreateHook(&NtCreateProcess, &hkNtCreateProcess, reinterpret_cast<LPVOID*>(&oNtCreateProcess));
	MH_EnableHook(&NtCreateProcess);
	MH_CreateHook(&DecodePointer, &hkDecodePointer, reinterpret_cast<LPVOID*>(&oDecodePointer));
	MH_EnableHook(&DecodePointer);
	MH_CreateHook(&EncodePointer, &hkEncodePointer, reinterpret_cast<LPVOID*>(&oEncodePointer));
	MH_EnableHook(&EncodePointer);

	for (;;) { Sleep(500); }
}
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved)
{
        switch ( ul_reason_for_call ) {
        case DLL_PROCESS_ATTACH:
           // DisableThreadLibraryCalls(hModule);
			AllocConsole();
			freopen_s((FILE**)stdout, "CONOUT$", "w", stdout);
			std::cout << "monitor loaded" << std::endl;
			//real_dll_init();
			CreateThread(NULL, NULL, Looper, NULL, NULL, NULL);
            break;
        case DLL_PROCESS_DETACH:
          //  if ( !lpReserved )
               // real_dll_free();
            break;
        default:
             break;
        }
        return TRUE;
}
