#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>

#ifndef __Chacha_h__
#define __Chacha_h__

#define CHACHA_BLOCKLENGTH 64

typedef struct {
	UINT input[16];
} CHACHA_CONTEXT;

void chachaKeySetup(CHACHA_CONTEXT* x, const BYTE* key);
void chachaNonceSetup(CHACHA_CONTEXT* x, const BYTE* nonce);
void chachaEncrypt(CHACHA_CONTEXT* x, const BYTE* inbuf, BYTE* outbuf, UINT length);

#endif
