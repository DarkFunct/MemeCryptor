#include "Threading.h"
THREAD_STRUCT threadStruct;

int threadEncrypt(THREAD_STRUCT* pThreadStruct) {
	// make sure cryptinit has been called already
	// TODO: Write this
	return 0;
}

int initThreadStruct() {
	THREAD_STRUCT* pThreadStruct = &threadStruct;
	pThreadStruct->filePath = NULL;

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