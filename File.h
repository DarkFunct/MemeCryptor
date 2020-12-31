#pragma once
#include "windows.h"
#include "restartmanager.h"
#pragma comment(lib, "rstrtmgr.lib")
#include "tlhelp32.h"

#ifndef __File_h__
#define __File_h__

struct EXPL_NODE {
	DWORD id;
	struct EXPL_NODE* nextNode;
};

typedef BOOL(WINAPI* MemeCloseHandle)(HANDLE hObject);

typedef HANDLE(WINAPI* MemeCreateToolhelp32Snapshot)(DWORD dwFlags, DWORD th32ProcessID);

typedef BOOL(WINAPI* MemeProcess32FirstW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

typedef int(WINAPI* MemelstrcmpiW)(LPCWSTR lpString1, LPCWSTR lpString2);

typedef BOOL(WINAPI* MemeProcess32NextW)(HANDLE hSnapshot, LPPROCESSENTRY32W lppe);

typedef int(WINAPI* MemeMultiByteToWideChar)(UINT CodePage, DWORD dwFlags, LPCCH lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar);

typedef DWORD(WINAPI* MemeRmStartSession)(DWORD* pSessionHandle, DWORD dwSessionFlags, WCHAR* strSessionKey);

typedef DWORD(WINAPI* MemeRmRegisterResources)(DWORD dwSessionHandle, UINT nFiles, LPCWSTR* rgsFileNames, UINT nApplications, RM_UNIQUE_PROCESS* rgApplications, UINT nServices, LPCWSTR* rgsServiceNames);

typedef DWORD(WINAPI* MemeRmGetList)(DWORD dwSessionHandle, UINT* pnProcInfoNeeded, UINT* pnProcInfo, RM_PROCESS_INFO* rgAffectedApps, LPDWORD lpdwRebootReasons);

typedef HANDLE(WINAPI* MemeGetCurrentProcess)();

typedef DWORD(WINAPI* MemeGetProcessId)(HANDLE Process);

typedef DWORD(WINAPI* MemeRmShutdown)(DWORD dwSessionHandle, ULONG lActionFlags, RM_WRITE_STATUS_CALLBACK fnStatus);

typedef DWORD(WINAPI* MemeRmEndSession)(DWORD dwSessionHandle);

extern EXPL_NODE* EXPLORER_ID_LL;

void killFileOwner(LPSTR fileName);

void findExplorerExe();

void cleanExplorerLL();
#endif