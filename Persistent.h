#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>

#ifndef __Persistent_h__
#define __Persistent_h__
extern LPCSTR tempFile_path;
#endif

int createTemp();


int mainPersist(BOOL start);