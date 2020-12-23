// MemeCryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

using namespace std;
#include "Persistent.h"
#include "Crypto.h"
int main()
{
	HANDLE inFile = CreateFileA("C:\\Users\\DongChuong\\Desktop\\Reverse engineering\\PUBLICKEY_encrypted.txt", GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	HANDLE outFile = CreateFileA("C:\\Users\\DongChuong\\Desktop\\Reverse engineering\\encrypted_output.txt", GENERIC_WRITE, FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
	const BYTE key[] = { 17, 19, 79, 87, 73, 56, 6, 61, 77, 94, 10, 37, 63, 66, 32, 50, 6, 60, 19, 61, 12, 48, 35, 97, 33, 78, 17, 96, 5, 64, 86, 66, 98, 99, 78, 56, 71, 67, 32, 60, 25, 42, 74, 75, 41, 37, 67, 59, 80, 18, 2, 90, 84, 42, 44, 81, 79, 35, 9, 2, 21, 56, 81, 23, 47, 3, 84, 11, 100, 47, 17, 81, 65, 76, 3, 64, 30, 2, 98, 35, 28, 66, 65, 98, 68, 92, 69, 23, 72, 0, 77, 71, 43, 85, 1, 54, 32, 16, 61, 26, 69, 66, 51, 46, 46, 82, 5, 84, 84, 53, 0, 63, 95, 31, 6, 51, 75, 37, 56, 79, 77, 15, 37, 93, 82, 80, 59, 0, 46, 90, 30, 90, 18, 46, 10, 1, 43, 69, 10, 52, 99, 31, 49, 99, 68, 7, 78, 81, 33, 41, 4, 22, 21, 3, 60, 10, 66, 85, 6, 80, 96, 84, 63, 23, 3, 63, 33, 60, 9, 70, 23, 24, 36, 7, 51, 96, 74, 33, 91, 48, 57, 90, 3, 6, 86, 8, 48, 63, 92, 15, 17, 29, 66, 10, 68, 87, 88, 48, 81, 54, 48, 34, 86, 70, 74, 85, 25, 75, 34, 9, 52, 97, 97, 33, 16, 7, 62, 34, 77, 98, 27, 29, 48, 99, 97, 57, 21, 61, 6, 99, 77, 52, 91, 100, 74, 36, 8, 41, 32, 39, 72, 1, 20, 7, 33, 82, 44, 89, 60, 27, 33, 95, 5, 86, 99, 54 };
	const BYTE nonce[] = { 1, 2, 3, 4, 5, 6, 7, 8 };


	chachaFileEncrypt(inFile, outFile, key, nonce);

	CloseHandle(inFile);
	CloseHandle(outFile);
}
