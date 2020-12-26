#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>
#include "Chacha.h"
#ifndef __Crypto_h__
#define __Crypto_h__
extern HCRYPTPROV hCryptProv;
extern BYTE publicKeyBlob[532];

int cryptInit();

void cryptCleanUp();

// main file encryption function
// 9406ms for 1024mb file, 4706ms for 512mb, 1833ms for 200mb, 924ms for 100mb, 474ms for 50mb, 9ms for 1mb, 92ms for 10mb
int fileEncrypt(LPCSTR oriFileName, BYTE* key, BYTE* nonce);
DWORD getLengthString(LPCSTR oriFileName);
#endif

