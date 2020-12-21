#include "Crypto.h"
HCRYPTPROV hCryptProv;
int cryptInit() {
	if (CryptAcquireContext(&hCryptProv, NULL, NULL, PROV_RSA_AES, 0)) {
		printf("CryptAcquireContext succeeds.\n");
	}
	else {
		printf("CryptAcquireContext fails.\n");
		return -1;
	}

	return 0;
}


void cryptCleanUp() {
	if (hCryptProv != NULL) {
		CryptReleaseContext(hCryptProv, 0);
	}
}