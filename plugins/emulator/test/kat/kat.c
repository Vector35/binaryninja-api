/*
 * Known-answer-test kernels for the BNIL emulator.
 *
 * These are deliberately *freestanding*: no libc, no syscalls, no process
 * startup. Each entry point is a pure function over caller-supplied buffers, so
 * the emulator can be pointed straight at it with arguments placed by the
 * calling convention. That keeps the emulator core under test rather than the
 * libc stub layer.
 *
 * Everything here is portable C with no intrinsics. The build additionally
 * disables builtins and autovectorization so the compiler cannot turn these
 * loops into memcpy/memset calls or SIMD, which the emulator would have to
 * service through an intrinsic hook rather than execute.
 *
 * The algorithms are chosen because they are self-checking against published
 * test vectors and are dense in exactly the operations that are easy to get
 * subtly wrong: 32-bit rotates, wrapping addition, shift/mask chains, and
 * table-driven loads.
 */

typedef unsigned char u8;
typedef unsigned int u32;
typedef unsigned long long u64;

/* ------------------------------------------------------------------ */
/* base64 (RFC 4648)                                                   */
/* ------------------------------------------------------------------ */

static const char B64[64] =
	"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* Encode inlen bytes at in into out, NUL-terminated. Returns encoded length. */
unsigned long b64_encode(const u8 *in, unsigned long inlen, char *out)
{
	unsigned long i = 0, o = 0, rem;

	while (i + 3 <= inlen)
	{
		u32 v = ((u32)in[i] << 16) | ((u32)in[i + 1] << 8) | (u32)in[i + 2];
		out[o++] = B64[(v >> 18) & 63];
		out[o++] = B64[(v >> 12) & 63];
		out[o++] = B64[(v >> 6) & 63];
		out[o++] = B64[v & 63];
		i += 3;
	}

	rem = inlen - i;
	if (rem == 1)
	{
		u32 v = (u32)in[i] << 16;
		out[o++] = B64[(v >> 18) & 63];
		out[o++] = B64[(v >> 12) & 63];
		out[o++] = '=';
		out[o++] = '=';
	}
	else if (rem == 2)
	{
		u32 v = ((u32)in[i] << 16) | ((u32)in[i + 1] << 8);
		out[o++] = B64[(v >> 18) & 63];
		out[o++] = B64[(v >> 12) & 63];
		out[o++] = B64[(v >> 6) & 63];
		out[o++] = '=';
	}

	out[o] = 0;
	return o;
}

/* ------------------------------------------------------------------ */
/* MD5 (RFC 1321)                                                      */
/* ------------------------------------------------------------------ */

static const u32 MD5_K[64] = {
	0xd76aa478u, 0xe8c7b756u, 0x242070dbu, 0xc1bdceeeu,
	0xf57c0fafu, 0x4787c62au, 0xa8304613u, 0xfd469501u,
	0x698098d8u, 0x8b44f7afu, 0xffff5bb1u, 0x895cd7beu,
	0x6b901122u, 0xfd987193u, 0xa679438eu, 0x49b40821u,
	0xf61e2562u, 0xc040b340u, 0x265e5a51u, 0xe9b6c7aau,
	0xd62f105du, 0x02441453u, 0xd8a1e681u, 0xe7d3fbc8u,
	0x21e1cde6u, 0xc33707d6u, 0xf4d50d87u, 0x455a14edu,
	0xa9e3e905u, 0xfcefa3f8u, 0x676f02d9u, 0x8d2a4c8au,
	0xfffa3942u, 0x8771f681u, 0x6d9d6122u, 0xfde5380cu,
	0xa4beea44u, 0x4bdecfa9u, 0xf6bb4b60u, 0xbebfbc70u,
	0x289b7ec6u, 0xeaa127fau, 0xd4ef3085u, 0x04881d05u,
	0xd9d4d039u, 0xe6db99e5u, 0x1fa27cf8u, 0xc4ac5665u,
	0xf4292244u, 0x432aff97u, 0xab9423a7u, 0xfc93a039u,
	0x655b59c3u, 0x8f0ccc92u, 0xffeff47du, 0x85845dd1u,
	0x6fa87e4fu, 0xfe2ce6e0u, 0xa3014314u, 0x4e0811a1u,
	0xf7537e82u, 0xbd3af235u, 0x2ad7d2bbu, 0xeb86d391u,
};

static const u8 MD5_S[64] = {
	7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
	5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
	4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
	6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21,
};

#define ROTL32(x, c) (((x) << (c)) | ((x) >> (32 - (c))))

/* One-shot MD5 over len bytes at msg; writes 16 bytes to digest. */
void md5(const u8 *msg, unsigned long len, u8 *digest)
{
	u32 h0 = 0x67452301u, h1 = 0xefcdab89u, h2 = 0x98badcfeu, h3 = 0x10325476u;
	u64 bitlen = (u64)len * 8;
	unsigned long total, off;
	int i, j;

	/* Padded length: message + 0x80 + zeros until 56 mod 64, + 8 length bytes. */
	total = len + 1;
	while ((total & 63) != 56)
		total++;
	total += 8;

	for (off = 0; off < total; off += 64)
	{
		u8 block[64];
		u32 M[16];
		u32 A, B, C, D;

		/* Materialize this block, synthesizing padding past the message end. */
		for (j = 0; j < 64; j++)
		{
			unsigned long idx = off + (unsigned long)j;
			u8 b;
			if (idx < len)
				b = msg[idx];
			else if (idx == len)
				b = 0x80;
			else if (idx >= total - 8)
				b = (u8)(bitlen >> (8 * (idx - (total - 8))));
			else
				b = 0;
			block[j] = b;
		}

		for (j = 0; j < 16; j++)
			M[j] = (u32)block[j * 4] | ((u32)block[j * 4 + 1] << 8)
				| ((u32)block[j * 4 + 2] << 16) | ((u32)block[j * 4 + 3] << 24);

		A = h0; B = h1; C = h2; D = h3;
		for (j = 0; j < 64; j++)
		{
			u32 F, x, tmp;
			int g;
			if (j < 16)      { F = (B & C) | (~B & D);  g = j; }
			else if (j < 32) { F = (D & B) | (~D & C);  g = (5 * j + 1) & 15; }
			else if (j < 48) { F = B ^ C ^ D;           g = (3 * j + 5) & 15; }
			else             { F = C ^ (B | ~D);        g = (7 * j) & 15; }

			tmp = D; D = C; C = B;
			x = A + F + MD5_K[j] + M[g];
			B = B + ROTL32(x, MD5_S[j]);
			A = tmp;
		}

		h0 += A; h1 += B; h2 += C; h3 += D;
	}

	{
		u32 h[4];
		h[0] = h0; h[1] = h1; h[2] = h2; h[3] = h3;
		for (i = 0; i < 4; i++)
			for (j = 0; j < 4; j++)
				digest[i * 4 + j] = (u8)(h[i] >> (8 * j));
	}
}
