#include "sm4.h"
#include <time.h>

void sm4_self_check()
{
	// plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	// key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	// cipher: 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46	
	uint8_t key[SM4_KEY_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, };
	uint8_t plain[SM4_BLOCK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10, };
	uint8_t expected[SM4_BLOCK_SIZE] = { 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46, };
	uint8_t cipher[SM4_BLOCK_SIZE] = { 0 };
	uint8_t decrypted[SM4_BLOCK_SIZE] = { 0 };
	uint32_t rkey[SM4_KEY_SCHEDULE] = { 0 };

	sm4_key_schedule(key, rkey);
	// puts("Round key:");
	// print_uchar((uint8_t*)rkey, SM4_KEY_SCHEDULE * 4);

	//sm4_enc(plain, cipher, rkey);
	sm4_enc_ex(plain, cipher, rkey);

	// should be: 0x68, 0x1e, 0xdf, 0x34, 0xd2, 0x06, 0x96, 0x5e, 0x86, 0xb3, 0xe9, 0x4f, 0x53, 0x6e, 0x42, 0x46,
	// puts("CipherText:");
	// print_uchar(cipher, SM4_BLOCK_SIZE);
	if (memcmp(cipher, expected, SM4_BLOCK_SIZE) != 0)
	{
		puts("SM4Fast encrypt test failed.");
		exit(0);
	}

	sm4_dec(cipher, decrypted, rkey);

	//print_uchar(block, SM4_BLOCK_SIZE);
	if (memcmp(decrypted, plain, SM4_BLOCK_SIZE) != 0)
	{
		puts("SM4Fast decrypt test failed.");

		//puts("Decrypted text:");
		//print_uchar(decrypted, SM4_BLOCK_SIZE);

		//puts("Plain text:");
		//print_uchar(plain, SM4_BLOCK_SIZE);

		exit(0);
	}

	puts("SM4Fast self test passed.");
	puts("\n");
}

void sm4_benchmark()
{
	size_t n = 10000000;
	clock_t t1, t2;
	uint32_t i = 0;
	double diff, speed;

	// plain: 01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	// key:   01 23 45 67 89 ab cd ef fe dc ba 98 76 54 32 10
	// cipher: 68 1e df 34 d2 06 96 5e 86 b3 e9 4f 53 6e 42 46	
	uint8_t key[SM4_KEY_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	uint8_t plain[SM4_BLOCK_SIZE] = { 0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10 };
	uint8_t cipher[SM4_BLOCK_SIZE];

	uint32_t rkey[SM4_KEY_SCHEDULE];
	sm4_key_schedule(key, rkey);

	t1 = clock();
	for (i = 0; i < n; i++)
	{
		//sm4_enc(plain, cipher, rkey);
		sm4_enc_ex(plain, cipher, rkey);
	}
	t2 = clock();
	diff = t2 - t1;
	diff = diff / CLOCKS_PER_SEC;
	speed = (1.0 * n * SM4_BLOCK_SIZE / 1024 / 1024) / diff;
	printf("Run %u times in %.3f seconds\n", n, diff);
	printf("sm4fast speed %.3f MB/sec\n\n", speed);
}

int main()
{
	sm4_self_check();
	sm4_benchmark();

	return 0;
}

