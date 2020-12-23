#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>

#ifndef __Crypto_h__
#define __Crypto_h__
extern HCRYPTPROV hCryptProv;
#endif


int cryptInit();
void cryptCleanUp();
