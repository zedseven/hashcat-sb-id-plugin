/**
 * Author......: See docs/credits.txt
 * License.....: MIT
 * Based on kernels `m01410_a3-pure.cl` (fast SHA-256 kernel) and `m00500-pure.cl` (slow MD5 iterated kernel)
 */

#define NEW_SIMD_CODE

#ifdef KERNEL_STATIC
#include M2S(INCLUDE_PATH/inc_vendor.h)
#include M2S(INCLUDE_PATH/inc_types.h)
#include M2S(INCLUDE_PATH/inc_platform.cl)
#include M2S(INCLUDE_PATH/inc_common.cl)
#include M2S(INCLUDE_PATH/inc_hash_sha256.cl)

#include M2S(INCLUDE_PATH/m97700-pure.h)
#endif

#define COMPARE_M M2S(INCLUDE_PATH/inc_comp_multi.cl)

u32 u8_len_to_u32_len(u32 len)
{
	return len / U8S_PER_U32 + (len % U8S_PER_U32 == 0 ? 0 : 1);
}

void print_debug_info(sb_tmp_t *tmp)
{
	u32 u32_len = u8_len_to_u32_len(tmp->digest_len);
	printf("len: %d", tmp->digest_len);
	for (u32 i = 0; i < u32_len; i++) {
		if (i % 16 == 0) {
			printf("\n%08x", tmp->digest_buf[i]);
		} else {
			printf(" %08x", tmp->digest_buf[i]);
		}
	}
	printf("\n");
}

void to_ascii_hex_representation(u32 *destination, u32 num)
{
	// Converts a nibble into its corresponding ASCII hex representation, in byte format
	const u32 lookup_table[16] = {
		0x30, 0x31, 0x32, 0x33,
		0x34, 0x35, 0x36, 0x37,
		0x38, 0x39, 0x61, 0x62,
		0x63, 0x64, 0x65, 0x66
	};

	destination[0] =
		(lookup_table[(0xF0000000 & num) >> 28] << 24) |
		(lookup_table[(0x0F000000 & num) >> 24] << 16) |
		(lookup_table[(0x00F00000 & num) >> 20] <<  8) |
		 lookup_table[(0x000F0000 & num) >> 16];
	destination[1] =
		(lookup_table[(0x0000F000 & num) >> 12] << 24) |
		(lookup_table[(0x00000F00 & num) >>  8] << 16) |
		(lookup_table[(0x000000F0 & num) >>  4] <<  8) |
		 lookup_table[ 0x0000000F & num];
}

// For this algorithm, all that needs to be done during initialisation is to load the provided password
// into `tmps` for processing
KERNEL_FQ void m97700_init (KERN_ATTR_TMPS (sb_tmp_t))
{
	/**
	 * base
	 */

	const u64 gid = get_global_id(0);

	if (gid >= GID_CNT) return;

	/**
	 * init
	 */

	// Load the password provided in `pws` into the `digest_buf` field of `tmps`
	tmps[gid].digest_len = pws[gid].pw_len;

	for (u32 i = 0, idx = 0; i < pws[gid].pw_len; i += U8S_PER_U32, idx += 1)
	{
		// For some reason, Hashcat provides the password in little-endian byte order, so they need to be swapped
		tmps[gid].digest_buf[idx] = hc_swap32(pws[gid].i[idx]);
	}

//	printf("init\n");
}

// This is where the actual processing takes place
// LOOP_CNT is the number of loops to run in this instance of the `_loop` function
// LOOP_POS is the overall position out of the number of iterations to be run
KERNEL_FQ void m97700_loop (KERN_ATTR_TMPS (sb_tmp_t))
{
//	printf("loop (pos: %d, count: %d)\n", LOOP_POS, LOOP_CNT);
	/**
	 * base
	 */

	const u64 gid = get_global_id(0);

	if (gid >= GID_CNT) return;

	/**
	 * loop
	 */

	for (u32 i = 0, j = LOOP_POS; i < LOOP_CNT; i++, j++)
	{
//		print_debug_info(&tmps[gid]);

		// Process the value with SHA-256
		sha256_ctx_t ctx = {0};

		sha256_init(&ctx);

		sha256_update(&ctx, tmps[gid].digest_buf, tmps[gid].digest_len); // The length provided to this function is in u8s, not u32s

		sha256_final(&ctx);

		// On the final iteration, we don't want to convert the digest into the ASCII hex representations
		if (j != NUM_ITERATIONS - 1)
		{
			// Convert the raw integers into their ASCII hex representations :)
			for (u32 k = 0; k < HASH_U32_LENGTH; k++)
			{
				to_ascii_hex_representation(&tmps[gid].digest_buf[k * ASCII_CHARACTERS_PER_U8], ctx.h[k]);
			}

			// Optimisation: all digests after the first iteration will always be the same length, so this is only necessary at the beginning
			if (j == 0)
			{
				// Set the new digest length
				tmps[gid].digest_len = HASH_U32_LENGTH * ASCII_CHARACTERS_PER_U8 * U8S_PER_U32;

				// Zero the remaining bytes in the digest
				memset(&tmps[gid].digest_buf[HASH_U32_LENGTH * ASCII_CHARACTERS_PER_U8],
					   0,
					   STORED_DIGEST_SIZE - HASH_U32_LENGTH * ASCII_CHARACTERS_PER_U8);
			}
		}
		else
		{
			// Copy the final digest back out
			memcpy(&tmps[gid].digest_buf, &ctx.h, HASH_U32_LENGTH * U8S_PER_U32);

			// No need to zero the remainder of the digest, since there will be no more iterations
		}
	}

	// Since we modify `tmps[gid].digest_buf` in-place, there's nothing else to do at the end of the loop
}

// This is where the comparison happens, to see if it's a match
KERNEL_FQ void m97700_comp (KERN_ATTR_TMPS (sb_tmp_t))
{
//	printf("comp\n");
	/**
	 * modifier
	 */

	const u64 gid = get_global_id(0);

	if (gid >= GID_CNT) return;

	const u64 lid = get_local_id(0);

	/**
	 * digest
	 */

	// Prepare the values we care about for the comparison
	const u32 r0 = tmps[gid].digest_buf[DGST_R0];
	const u32 r1 = tmps[gid].digest_buf[DGST_R1];
	const u32 r2 = tmps[gid].digest_buf[DGST_R2];
	const u32 r3 = tmps[gid].digest_buf[DGST_R3];

//	printf("%08x %08x %08x %08x\n", r0, r1, r2, r3);

#define il_pos 0

	// This actually does the comparison
#ifdef KERNEL_STATIC
#include COMPARE_M
#endif
}
