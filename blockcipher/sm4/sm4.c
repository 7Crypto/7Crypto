#include "sm4.h"

// Erase buffer by random data
// Generally, the buffer should not be very large, e.g. the key
static void erase_data(void* buf, u4 buflen)
{
	memset(buf, buflen, buflen);
}


inline static u4 rotate(u4 input)
{
	return ((input & 0xff) << 24) | (((input >> 8) & 0xff) << 16) | (((input >> 16) & 0xff) << 8) | (((input >> 24) & 0xff));
}

inline static u4 rotate_left(u4 x, u1 shift)
{
	return (x << shift) | (x >> (-shift & 31));
}

inline static u4 load_u32_be(const u1 *b, u4 n)
{
	return ((u4)b[4 * n] << 24) |
		((u4)b[4 * n + 1] << 16) |
		((u4)b[4 * n + 2] << 8) |
		((u4)b[4 * n + 3]);
}

inline static void store_u32_be(u4 v, u1 *b)
{
	b[0] = (u1)(v >> 24);
	b[1] = (u1)(v >> 16);
	b[2] = (u1)(v >> 8);
	b[3] = (u1)(v);
}

// (  (u1*)(&input)  )[3-byte_num]
inline static u1 get_byte(size_t byte_num, u4 input)
{
	return (u1)(input >> ((3 - byte_num) * 8));
}

//#define NEED_DEBUG
inline static u4 F(u4 b)
{
	const u4 t = Sbox_T24[get_byte(0, b)] ^ Sbox_T16[get_byte(1, b)] ^ Sbox_T8[get_byte(2, b)] ^ Sbox_T[get_byte(3, b)];
	return t;
}

// Make a u4 from four bytes
// return i0 || i1 || i2 || i3
inline static u4 make_u4(u1 i0, u1 i1, u1 i2, u1 i3)
{
	return (((u4)(i0)) << 24) |
		(((u4)(i1)) << 16) |
		(((u4)(i2)) << 8) |
		((u4)(i3));
}

// Variant of T for key schedule
inline static u4 sm4_tp(u4 b)
{
	const u4 t = make_u4(Sbox[get_byte(0, b)], Sbox[get_byte(1, b)], Sbox[get_byte(2, b)], Sbox[get_byte(3, b)]);

	// L' linear transform
	return t ^ rotate_left(t, 13) ^ rotate_left(t, 23);
}

#define SM4_RNDS(B, k0, k1, k2, k3) {   \
  B[0] ^= F(B[1] ^ B[2] ^ B[3] ^ rkey[k0]); \
  B[1] ^= F(B[0] ^ B[2] ^ B[3] ^ rkey[k1]); \
  B[2] ^= F(B[0] ^ B[1] ^ B[3] ^ rkey[k2]); \
  B[3] ^= F(B[0] ^ B[1] ^ B[2] ^ rkey[k3]); \
}

// SM4 Encryption, the src and dst can be equal(The same pointer)
void sm4_enc(const u1 src[SM4_BLOCK_SIZE], u1 dst[SM4_BLOCK_SIZE], const u4 rkey[SM4_KEY_SCHEDULE])
{
	u1 buf[SM4_BLOCK_SIZE] = { 0 };
	u4* ptr = (u4*)buf;
	u4* ptr2 = (u4*)dst;
	memcpy(ptr, src, SM4_BLOCK_SIZE);

	SM4_RNDS(ptr, 0, 1, 2, 3);
	SM4_RNDS(ptr, 4, 5, 6, 7);
	SM4_RNDS(ptr, 8, 9, 10, 11);
	SM4_RNDS(ptr, 12, 13, 14, 15);
	SM4_RNDS(ptr, 16, 17, 18, 19);
	SM4_RNDS(ptr, 20, 21, 22, 23);
	SM4_RNDS(ptr, 24, 25, 26, 27);
	SM4_RNDS(ptr, 28, 29, 30, 31);

	ptr2[0] = ptr[3];
	ptr2[1] = ptr[2];
	ptr2[2] = ptr[1];
	ptr2[3] = ptr[0];

	erase_data(buf, sizeof(buf));
}

// SM4 Decryption, the src and dst can be equal(The same pointer)
void sm4_dec(const u1 src[SM4_BLOCK_SIZE], u1 dst[SM4_BLOCK_SIZE], const u4 rkey[SM4_KEY_SCHEDULE])
{
	u1 buf[SM4_BLOCK_SIZE] = { 0 };
	u4* ptr = (u4*)buf;
	u4* ptr2 = (u4*)dst;
	memcpy(ptr, src, SM4_BLOCK_SIZE);

	SM4_RNDS(ptr, 31, 30, 29, 28);
	SM4_RNDS(ptr, 27, 26, 25, 24);
	SM4_RNDS(ptr, 23, 22, 21, 20);
	SM4_RNDS(ptr, 19, 18, 17, 16);
	SM4_RNDS(ptr, 15, 14, 13, 12);
	SM4_RNDS(ptr, 11, 10, 9, 8);
	SM4_RNDS(ptr, 7, 6, 5, 4);
	SM4_RNDS(ptr, 3, 2, 1, 0);

	ptr2[0] = ptr[3];
	ptr2[1] = ptr[2];
	ptr2[2] = ptr[1];
	ptr2[3] = ptr[0];

	erase_data(buf, sizeof(buf));
}

// SM4 key schedule: The rkey will differ from the tranditional one, since the endian of each 'u4' is consverted.
void sm4_key_schedule(const u1 key[SM4_KEY_SIZE], u4 rkey[SM4_KEY_SCHEDULE])
{
	u4 i = 0;

	// System parameter or family key
	static const u4 FK[4] = { 0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc };
	static const u4 CK[SM4_KEY_SCHEDULE] =
	{
		0x00070E15, 0x1C232A31, 0x383F464D, 0x545B6269,
		0x70777E85, 0x8C939AA1, 0xA8AFB6BD, 0xC4CBD2D9,
		0xE0E7EEF5, 0xFC030A11, 0x181F262D, 0x343B4249,
		0x50575E65, 0x6C737A81, 0x888F969D, 0xA4ABB2B9,
		0xC0C7CED5, 0xDCE3EAF1, 0xF8FF060D, 0x141B2229,
		0x30373E45, 0x4C535A61, 0x686F767D, 0x848B9299,
		0xA0A7AEB5, 0xBCC3CAD1, 0xD8DFE6ED, 0xF4FB0209,
		0x10171E25, 0x2C333A41, 0x484F565D, 0x646B7279
	};
	u4 K[4] = { 0 };

	K[0] = load_u32_be(key, 0) ^ FK[0];
	K[1] = load_u32_be(key, 1) ^ FK[1];
	K[2] = load_u32_be(key, 2) ^ FK[2];
	K[3] = load_u32_be(key, 3) ^ FK[3];

	for (i = 0; i < SM4_KEY_SCHEDULE; i++)
	{
		K[i % 4] ^= sm4_tp(K[(i + 1) % 4] ^ K[(i + 2) % 4] ^ K[(i + 3) % 4] ^ CK[i]);
		rkey[i] = K[i % 4];
	}

	// Rotate the round key in this special condition [The encrypted result will differ from the tranditional one]
	for (i = 0; i < SM4_KEY_SCHEDULE; i++)
	{
		rkey[i] = rotate(rkey[i]);
	}

	erase_data(K, sizeof(K));
}


