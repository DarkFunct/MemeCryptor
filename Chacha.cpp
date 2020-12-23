#include "Chacha.h"

#define U8V(v)  ((uint8_t)(v)  & UINT8_C(0xFF))
#define U32V(v) ((uint32_t)(v) & UINT32_C(0xFFFFFFFF))

#define U8TO32_LITTLE(p) \
  (((uint32_t)((p)[0])      ) | \
   ((uint32_t)((p)[1]) <<  8) | \
   ((uint32_t)((p)[2]) << 16) | \
   ((uint32_t)((p)[3]) << 24))

#define U32TO8_LITTLE(p, v) \
  do { \
    (p)[0] = U8V((v)      ); \
    (p)[1] = U8V((v) >>  8); \
    (p)[2] = U8V((v) >> 16); \
    (p)[3] = U8V((v) >> 24); \
  } while (0)

#define ROTATE(v,c) (U32V((v) << (c)) | ((v) >> (32 - (c))))
#define XOR(v,w) ((v) ^ (w))
#define PLUS(v,w) (U32V((v) + (w)))
#define PLUSONE(v) (PLUS((v),1))

#define QUARTERROUND(a,b,c,d) \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]),16); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]),12); \
  x[a] = PLUS(x[a],x[b]); x[d] = ROTATE(XOR(x[d],x[a]), 8); \
  x[c] = PLUS(x[c],x[d]); x[b] = ROTATE(XOR(x[b],x[c]), 7);


static const char sigma[16] = { 0x65, 0x78, 0x70, 0x61, 0x6e, 0x64, 0x20, 0x33, 0x32, 0x2d, 0x62, 0x79, 0x74, 0x65, 0x20, 0x6b };

static void chachaWordToByte(BYTE output[64], const UINT input[16]) {
	uint32_t x[16];
	int i;

	for (i = 0; i < 16; ++i) {
		x[i] = input[i];
	}

	for (i = 8; i > 0; i -= 2) {
		QUARTERROUND(0, 4, 8, 12);
		QUARTERROUND(1, 5, 9, 13);
		QUARTERROUND(2, 6, 10, 14);
		QUARTERROUND(3, 7, 11, 15);
		QUARTERROUND(0, 5, 10, 15);
		QUARTERROUND(1, 6, 11, 12);
		QUARTERROUND(2, 7, 8, 13);
		QUARTERROUND(3, 4, 9, 14);
	}
	for (i = 0; i < 16; ++i) {
		x[i] = PLUS(x[i], input[i]);
	}
	for (i = 0; i < 16; ++i) {
		U32TO8_LITTLE(output + 4 * i, x[i]);
	}
}

void chachaKeySetup(CHACHA_CONTEXT* x, const BYTE* key)
{
	const char* constants;

	x->input[4] = U8TO32_LITTLE(key + 0);
	x->input[5] = U8TO32_LITTLE(key + 4);
	x->input[6] = U8TO32_LITTLE(key + 8);
	x->input[7] = U8TO32_LITTLE(key + 12);

	key += 16;
	constants = sigma;

	x->input[8] = U8TO32_LITTLE(key + 0);
	x->input[9] = U8TO32_LITTLE(key + 4);
	x->input[10] = U8TO32_LITTLE(key + 8);
	x->input[11] = U8TO32_LITTLE(key + 12);
	x->input[0] = U8TO32_LITTLE(constants + 0);
	x->input[1] = U8TO32_LITTLE(constants + 4);
	x->input[2] = U8TO32_LITTLE(constants + 8);
	x->input[3] = U8TO32_LITTLE(constants + 12);
}

void chachaNonceSetup(CHACHA_CONTEXT* x, const BYTE* nonce)
{
	x->input[12] = 0;
	x->input[13] = 0;
	x->input[14] = U8TO32_LITTLE(nonce + 0);
	x->input[15] = U8TO32_LITTLE(nonce + 4);
}


void chachaEncrypt(CHACHA_CONTEXT* x, const BYTE* inbuf, BYTE* outbuf, UINT length)
{
	uint8_t output[64];
	uint32_t i;

	if (!length) return;
	for (;;) {
		chachaWordToByte(output, x->input);
		x->input[12] = PLUSONE(x->input[12]);
		if (!x->input[12]) {
			x->input[13] = PLUSONE(x->input[13]);
			/* stopping at 2^70 bytes per nonce is user's responsibility */
		}
		if (length <= 64) {
			for (i = 0; i < length; ++i) {
				outbuf[i] = inbuf[i] ^ output[i];
			}
			return;
		}
		for (i = 0; i < 64; ++i) {
			outbuf[i] = inbuf[i] ^ output[i];
		}
		length -= 64;
		outbuf += 64;
		inbuf += 64;
	}
}