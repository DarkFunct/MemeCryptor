// MemeCryptor.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

using namespace std;
#include "Persistent.h"
#include "Crypto.h"
int main()
{
	cryptInit();
	// mainPersist(TRUE);

	// mainPersist(FALSE);
	cryptCleanUp();
}
