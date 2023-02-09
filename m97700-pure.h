// Constants
#define STORED_DIGEST_SIZE        16
#define U8S_PER_U32                4
#define HASH_U32_LENGTH            8 // The resulting hash length will always be 8 (8 * 32 bits = 256 bits)
#define ASCII_CHARACTERS_PER_U8    2 // 2 characters per byte in the ASCII hex representation
#define NUM_ITERATIONS          5000

// This is the structure where the program state is stored between loops
typedef struct sb_tmp
{
	u32 digest_buf[STORED_DIGEST_SIZE];
	u32 digest_len; // The length in u8s (4 u8s per u32)
} sb_tmp_t;
