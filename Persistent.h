#pragma once
#include "windows.h"
#include "Threading.h"
#include <iostream>
#include <stdio.h>

#ifndef __Persistent_h__
#define __Persistent_h__
extern LPCSTR tempFile_path;

int createTemp(HCRYPTPROV hCryptProv);
int mainPersist();
void persistCleanUp();

#endif