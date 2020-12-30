#pragma once
// Close file
// Find Drive

#include "windows.h"
#include "restartmanager.h"
#pragma comment(lib, "rstrtmgr.lib")
#include "tlhelp32.h"
#include <iostream>
#include <stdio.h>

#ifndef __File_h__
#define __File_h__

struct EXPL_NODE {
	DWORD id;
	struct EXPL_NODE* nextNode;
};

extern EXPL_NODE* EXPLORER_ID_LL;

void killFileOwner(LPSTR fileName);
void findExplorerExe();
void cleanExplorerLL();
#endif