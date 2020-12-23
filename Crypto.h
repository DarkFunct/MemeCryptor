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

// Make sure key size is 256, nonce size is 8
int chachaFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce);

#endif


