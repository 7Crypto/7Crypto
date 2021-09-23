#include"sm4.h"

extern const u4 Sbox_T24[256];
extern const u4 Sbox_T16[256];
extern const u4 Sbox_T8[256];
extern const u4 Sbox_T[256];

#define GET_U1(n, x) (u1)((x) >> (n))

#define F(x) Sbox_T24[GET_U1(24, x)] ^ Sbox_T16[GET_U1(16, x)] ^ Sbox_T8[GET_U1(8, x)] ^ Sbox_T[GET_U1(0, x)];

#define SM4_RNDS(A, B, C, D, k0, k1, k2, k3)\
	T = B ^ C ^ D ^ rkey[k0]; A ^= F(T); \
	T = C ^ D ^ A ^ rkey[k1]; B ^= F(T); \
	T = D ^ A ^ B ^ rkey[k2]; C ^= F(T); \
	T = A ^ B ^ C ^ rkey[k3]; D ^= F(T); \


// SM4 Encryption, the src and dst can be equal(The same pointer)
void sm4_enc_ex(const u1 src[SM4_BLOCK_SIZE], u1 dst[SM4_BLOCK_SIZE], const u4 rkey[SM4_KEY_SCHEDULE])
{
	u1 buf[SM4_BLOCK_SIZE] = { 0 };
	static u4 A, B, C, D, T;
	u4 * ptr1 = (u4 *)src;
	u4 * ptr2 = (u4 *)dst;

	A = ptr1[0]; 
	B = ptr1[1]; 
	C = ptr1[2]; 
	D = ptr1[3];

	SM4_RNDS(A, B, C, D,  0, 1,   2,  3);
	SM4_RNDS(A, B, C, D,  4, 5,   6,  7);
	SM4_RNDS(A, B, C, D,  8, 9,  10, 11);
	SM4_RNDS(A, B, C, D, 12, 13, 14, 15);
	SM4_RNDS(A, B, C, D, 16, 17, 18, 19);
	SM4_RNDS(A, B, C, D, 20, 21, 22, 23);
	SM4_RNDS(A, B, C, D, 24, 25, 26, 27);
	SM4_RNDS(A, B, C, D, 28, 29, 30, 31);

	ptr2[0] = D;
	ptr2[1] = C;
	ptr2[2] = B;
	ptr2[3] = A;

	memset(buf, sizeof(buf), sizeof(buf));
}

