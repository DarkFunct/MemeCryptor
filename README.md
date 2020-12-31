# MemeCryptor Ransomware
### Full scale ransomware that encrypts and embedded files in memes using Steganography


## 1. Motivation

Sometime ago, I came across this old tweet from [Michael Gillespie](https://twitter.com/demonslay335/status/1029749466176335872/photo/1) talking about badly-coded ransomware in the wild.

![alt text](/image/Inspiration.PNG)


This holds true to these days where I still come across way too many lame ransomware with mediocre encryption scheme and design pattern.


Just for fun, I decided to see if I could write a sophisticated ransomware using the techniques I have learned from analyzing samples from big families such as **Ryuk** and **Conti**.


For me, the best way to understand malware is to program them out myself. I hope by providing the source code, I can give other analysts out there a better understanding of ransomware as well as the different techniques that they use.


Also, most ransomware encryptions out there are relatively lame, so I decided to embed the encrypted files in memes just to spice things up.

## 2. Features
### Persistence

**MemeCryptor** immediately creates a copy of itself in the **Temp** directory under a random name, and it will add this path to *SOFTWARE\Microsoft\Windows\CurrentVersion\Run* to obtain persistence.

![alt text](/image/Registry.PNG)


### Run-once Mutex


**MemeCryptor** will attempt to decrypt the string *"wbizecif48njqgpprzkm6769"* and use that as the name of a Mutex object.

It checks if there is an instant of that Mutex running already. If there is, it will just wait until that thread exits before exiting.

### Hidden strings

For all strings that are used, I just implemented a simple xor encryption/decryption scheme and dynamically resolve each of them so they won't be detected by PE analysis tools.

``` cpp
// buffer = string to decrypt
// key is a random 5-byte buffer
// size is the size of the string
void resolveString(BYTE* buffer, BYTE* key, int size) {
	for (int i = 0; i < size; i++) {
		buffer[i] ^= 0xFF;
		buffer[i] ^= key[i % 5];
	}
}
```

### Hidden API (PE.cpp)

To hide API, **MemeCryptor** dynamically locates *Kernel32.dll*, goes through the EAT, and finds **GetProcAddress** and **GetModuleHandle**.

Then, it will resolve every API needed and store their addresses inside an array. 

This API array is then shared with other files to indirectly make needed API calls.

As a result, the **Import** section of the PE is completely empty beside the APIs needed by Visual Studio.

![alt text](/image/NoAPI.PNG)


### Encryption (Crypto.cpp)

Inspired by **Conti** ransomware, I decided to implement a multi-threading encryption scheme utitilizing 100% the victim's CPU by spawning as much threads as I can depending on the machine processor.

The child threads share one single linked-list structure in a queue form, and they continuously pop the head of the queue, retrieve a directory to encrypt, and encrypt it. When encountering a sub directory in the directory they are processing, they will add it to the back of the queue. The encryption stops when the queue is empty.


**MemeCryptor** stores a xor-encrypted **RSA** public key inside its source code. Each thread will decrypt this when they are spawned before using it to encrypt a randomly generated **ChaCha20** key.


Each **ChaCha20** key is used to encrypt a single file. The encrypted file will be appended at the end of this meme in **BMP** format.

![alt text](/image/meme.bmp)


The **ChaCha20** key is then written into the meme file using this **Steganography** trick I found [here](https://www.codeproject.com/Articles/5524/Hiding-a-text-file-in-a-bmp-file).


Using this encryption scheme, **MemeCryptor** can encrypt small files up to 100MB in under 1 second. For all files that are bigger than 100MB, the encryption is limited to 1.5 seconds exactly. As a result, it can crawl through the entire system in less than a minute.


### Windows Restart Manager (File.cpp)

By abusing the Windows Restart Manager, **MemeCryptor** can obtain a list of processes that are using files on the system.

With that information, it can force shutdown all of the processes that can prevent a file from being opened to be decrypted.

This was inspired by the implementations from **Conti** and **RegretLocker** Ransomware.


## 3. Disclaimer

This repo and its contents are only for educational purposes.

This executables being released are intended to be used solely by reverse engineers, analysts, and others who know how to handle malware.

The ransomware should only be ran in a VM environment. I accidentally ran it on my PC and encrypted around 200 GB of files before realizing, so please use it carefully.

Even though I have provided a decryptor, I can not 100% guarantee whether some file might be corrupted and unretrievable after encryption or not.

With that said, I am not to be held responsible by anyone to any lost or damaged property as a result of using this ransomware.

## 4. Acknowledgement

[Michael Gillespie](https://twitter.com/demonslay335?lang=en) -  for helping me learn a lot of these techniques and improve my analysis on ransomware samples

[0xastro](https://twitter.com/0xastr0) - https://github.com/0xastro/malwareanalysis/blob/main/Ryuk/Deep%20Dive%20Into%20Ryuk%20Ransomware.md

[VMWare Carbon Black TAU](https://www.carbonblack.com/threat-analysis-unit/) - https://www.carbonblack.com/blog/tau-threat-discovery-conti-ransomware/

[Myself ;)](http://chuongdong.com/) - http://chuongdong.com/reverse%20engineering/2020/12/15/ContiRansomware/

[AhmedOsamaMoh](https://www.codeproject.com/script/Membership/View.aspx?mid=193049) - https://www.codeproject.com/Articles/5524/Hiding-a-text-file-in-a-bmp-file

