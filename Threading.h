#pragma once
#include "Crypto.h"
#ifndef __Threading_h__
#define __Threading_h__

typedef struct {
	HANDLE* threadArray;
	DWORD threadCount;
	BOOL isEncrypting;
	CRITICAL_SECTION threadCriticalSection;
	LPSTR filePath;
	//DWORD drive_name_ptr;
} THREAD_STRUCT;

extern THREAD_STRUCT threadStruct;
int threadEncrypt(THREAD_STRUCT* pThreadStruct);
int initThreadStruct();
int launchThreadEncrypt();
void cleanUpThreadStruct();
#endif
