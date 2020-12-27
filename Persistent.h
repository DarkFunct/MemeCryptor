#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>

#ifndef __Persistent_h__
#define __Persistent_h__
extern LPCSTR tempFile_path;
#endif
int createTemp(HCRYPTPROV hCryptProv);


int mainPersist(BOOL start, HCRYPTPROV hCryptProv);


