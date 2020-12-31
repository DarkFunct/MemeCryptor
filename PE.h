#pragma once
#include <windows.h>

#ifndef __PE_h__
#define __PE_h__
//https://processhacker.sourceforge.io/doc/ntpsapi_8h_source.html#l00063
typedef struct PEB_LDR_DATA
{
	ULONG Length;
	BOOLEAN Initialized;
	HANDLE SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
	BOOLEAN ShutdownInProgress;
	HANDLE ShutdownThreadId;
};
//https://processhacker.sourceforge.io/doc/ntpebteb_8h_source.html#l00008
typedef struct PEB
{
	BOOLEAN InheritedAddressSpace;
	BOOLEAN ReadImageFileExecOptions;
	BOOLEAN BeingDebugged;
	union
	{
		BOOLEAN BitField;
		struct
		{
			BOOLEAN ImageUsesLargePages : 1;
			BOOLEAN IsProtectedProcess : 1;
			BOOLEAN IsImageDynamicallyRelocated : 1;
			BOOLEAN SkipPatchingUser32Forwarders : 1;
			BOOLEAN IsPackagedProcess : 1;
			BOOLEAN IsAppContainer : 1;
			BOOLEAN IsProtectedProcessLight : 1;
			BOOLEAN SpareBits : 1;
		};
	};
	HANDLE Mutant;
	PVOID ImageBaseAddress;
	PEB_LDR_DATA* Ldr;
	//there are more, but this is all we need
};

typedef struct UNICODE_STRING
{
	USHORT Length;
	USHORT MaximumLength;
	PWCH Buffer;
};

//https://processhacker.sourceforge.io/doc/ntldr_8h_source.html#l00102
typedef struct LDR_DATA_TABLE_ENTRY
{
	LIST_ENTRY InLoadOrderLinks;
	LIST_ENTRY InMemoryOrderLinks;
	union
	{
		LIST_ENTRY InInitializationOrderLinks;
		LIST_ENTRY InProgressLinks;
	};
	PVOID DllBase;
	PVOID EntryPoint;
	ULONG SizeOfImage;
	UNICODE_STRING FullDllName;
	UNICODE_STRING BaseDllName;
	//there are more, but this is all we need
};

typedef FARPROC(WINAPI* MemeGetProcAddress)(HMODULE hModule, LPCSTR lpProcName);

typedef HMODULE(WINAPI* MemeGetModuleHandleA)(LPCSTR lpModuleName);

typedef HMODULE(WINAPI* MemeLoadLibraryA)(LPCSTR lpLibFileName);
int initAPIArray();
#endif