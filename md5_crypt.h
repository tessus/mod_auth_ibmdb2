#ifndef MD5_CRYPT_H
#define MD5_CRYPT_H

#include <time.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef APACHE2
#include <crypt.h>
#endif

/* Definitions and Constants */

typedef unsigned long 		uint32;
typedef unsigned char		t_byte_t;
typedef short				t_int16_t;
typedef unsigned short		t_uint16_t;
typedef int					t_int32_t;
typedef unsigned int		t_uint32_t;
typedef long long			t_int64_t;
typedef unsigned long long	t_uint64_t;

typedef struct sha1_ctx_t sha1_ctx_t;

#define MD5_DIGESTSIZE 		16
#define SHA1_DIGESTSIZE 	20
#define SHA1PW_ID 			"{SHA}"
#define SHA1PW_IDLEN 		5
#define SIZEOF_VOIDP 		4

static const unsigned char pr2six[256] =
{
    /* ASCII table */
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 62, 64, 64, 64, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 64, 64, 64, 64, 64, 64,
    64,  0,  1,  2,  3,  4,  5,  6,  7,  8,  9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 64, 64, 64, 64, 64,
    64, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64,
    64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64, 64
};

static const char basis_64[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* a bit faster & bigger, if defined */
#define UNROLL_LOOPS

/* NIST's proposed modification to SHA, 7/11/94 */
#define USE_MODIFIED_SHA

/* SHA f()-functions */
#define f1(x,y,z)	((x & y) | (~x & z))
#define f2(x,y,z)	(x ^ y ^ z)
#define f3(x,y,z)	((x & y) | (x & z) | (y & z))
#define f4(x,y,z)	(x ^ y ^ z)

/* SHA constants */
#define CONST1		0x5a827999L
#define CONST2		0x6ed9eba1L
#define CONST3		0x8f1bbcdcL
#define CONST4		0xca62c1d6L

/* 32-bit rotate */

#define ROT32(x,n)	((x << n) | (x >> (32 - n)))

#define FUNC(n,i)						\
    temp = ROT32(A,5) + f##n(B,C,D) + E + W[i] + CONST##n;	\
    E = D; D = C; C = ROT32(B,30); B = A; A = temp

#define SHA_BLOCKSIZE           64

/* MD5 Algorithm */

#define S11 7
#define S12 12
#define S13 17
#define S14 22
#define S21 5
#define S22 9
#define S23 14
#define S24 20
#define S31 4
#define S32 11
#define S33 16
#define S34 23
#define S41 6
#define S42 10
#define S43 15
#define S44 21

/* F, G, H and I are basic MD5 functions.
 */
#define F(x, y, z) (((x) & (y)) | ((~x) & (z)))
#define G(x, y, z) (((x) & (z)) | ((y) & (~z)))
#define H(x, y, z) ((x) ^ (y) ^ (z))
#define I(x, y, z) ((y) ^ ((x) | (~z)))

/* ROTATE_LEFT rotates x left n bits.
 */
#define ROTATE_LEFT(x, n) (((x) << (n)) | ((x) >> (32-(n))))

/* FF, GG, HH, and II transformations for rounds 1, 2, 3, and 4.
   Rotation is separate from addition to prevent recomputation.
 */
#define FF(a, b, c, d, x, s, ac) { \
 (a) += F ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define GG(a, b, c, d, x, s, ac) { \
 (a) += G ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define HH(a, b, c, d, x, s, ac) { \
 (a) += H ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }
#define II(a, b, c, d, x, s, ac) { \
 (a) += I ((b), (c), (d)) + (x) + (uint32)(ac); \
 (a) = ROTATE_LEFT ((a), (s)); \
 (a) += (b); \
  }

static unsigned char PADDING[64] =
{
	0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/* MD5 context. */

typedef struct {
	uint32 state[4];				/* state (ABCD) */
	uint32 count[2];				/* number of bits, modulo 2^64 (lsb first) */
	unsigned char buffer[64];	/* input buffer */
} md5_ctx;

/* SHA1 context */
struct sha1_ctx_t {
    /** message digest */
    t_uint32_t digest[5];
    /** 64-bit bit counts */
    t_uint32_t count_lo, count_hi;
    /** SHA data buffer */
    t_uint32_t data[16];
    /** unprocessed amount in data */
    int local;
};

/* Prototypes */

static void to64(char *s, unsigned long v, int n);

void md5_init(md5_ctx *);
void md5_update(md5_ctx *, const unsigned char *, unsigned int);
void md5_final(unsigned char[16], md5_ctx *);
static void md5_transform(uint32 state[4], const unsigned char block[64]);
static void Encode(unsigned char *output, uint32 *input, unsigned int len);
static void Decode(uint32 *output, const unsigned char *input, unsigned int len);

char* md5( char *in );
char* encode_md5( char const *pw, char const *salt, char *ident_id );
char* sha1( char *clear );

void sha1_init(sha1_ctx_t *context);
void sha1_update(sha1_ctx_t *context, const char *input, unsigned int inputLen);
void sha1_update_binary(sha1_ctx_t *context, const unsigned char *input, unsigned int inputLen);
void sha1_final(unsigned char digest[SHA1_DIGESTSIZE], sha1_ctx_t *context);
static void maybe_byte_reverse(t_uint32_t *buffer, int count);
int base64_encode_len(int len);
int base64_encode(char * coded_dst, const char *plain_src, int len_plain_src);
int base64_encode_binary(char * coded_dst, const unsigned char *plain_src, int len_plain_src);
int base64_decode_len(const char * coded_src);
int base64_decode(char * plain_dst, const char *coded_src);
int base64_decode_binary(unsigned char * plain_dst, const char *coded_src);

/* Functions */

static void to64(char *s, unsigned long v, int n)
{
    static unsigned char itoa64[] =         /* 0 ... 63 => ASCII - 64 */
        "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

    while (--n >= 0) {
        *s++ = itoa64[v&0x3f];
        v >>= 6;
    }
}

char* md5( char *in )
{
    char *temp;
    char md5str[33];

	md5_ctx context;
	unsigned char digest[16];
	int i;
	char *r;

	temp = (char*)malloc(33*sizeof(char));
	md5str[0] = '\0';

	md5_init(&context);
	md5_update(&context, in, strlen(in));
	md5_final(digest, &context);
	for (i = 0, r = md5str; i < 16; i++, r += 2) {
		sprintf(r, "%02x", digest[i]);
	}
	*r = '\0';

	strcpy( temp, md5str );

	return temp;
}

char* encode_md5( const char *pw, const char *salt, char *ident_id )
{
	char passwd[120], *p;
	const char *sp, *ep;
	unsigned char final[MD5_DIGESTSIZE];
	md5_ctx ctx, ctx1;
	int sl, pl, i;
	unsigned long l;
	char *result;

	result = (char*)malloc(121*sizeof(char));

	sp = salt;

	if (!strncmp(sp, ident_id, strlen(ident_id)))
    {
	   sp += strlen(ident_id);
	}

	for (ep = sp; (*ep != '\0') && (*ep != '$') && (ep < (sp + 8)); ep++)
	{
	   continue;
    }

    sl = ep - sp;

	md5_init(&ctx);

	/*
	 * The password first, since that is what is most unknown
	 */
	md5_update(&ctx, pw, strlen(pw));

	/*
	 * Then our magic string
	 */
	md5_update(&ctx, ident_id, strlen(ident_id));

	/*
	 * Then the raw salt
	 */
	md5_update(&ctx, sp, sl);

	/*
	 * Then just as many characters of the MD5(pw, salt, pw)
	 */
	md5_init(&ctx1);
	md5_update(&ctx1, pw, strlen(pw));
	md5_update(&ctx1, sp, sl);
	md5_update(&ctx1, pw, strlen(pw));
	md5_final(final, &ctx1);
	for (pl = strlen(pw); pl > 0; pl -= MD5_DIGESTSIZE) {
	    md5_update(&ctx, final,
	                  (pl > MD5_DIGESTSIZE) ? MD5_DIGESTSIZE : pl);
	}

	/*
	 * Don't leave anything around in vm they could use.
	 */
	memset(final, 0, sizeof(final));

	/*
	 * Then something really weird...
	 */
	for (i = strlen(pw); i != 0; i >>= 1) {
	    if (i & 1) {
	        md5_update(&ctx, final, 1);
	    }
	    else {
	        md5_update(&ctx, pw, 1);
	    }
	}

	/*
	 * Now make the output string.  We know our limitations, so we
	 * can use the string routines without bounds checking.
	 */
	strcpy(passwd, ident_id);
	strncat(passwd, sp, sl);
	strcat(passwd, "$");

	md5_final(final, &ctx);

	/*
	 * And now, just to make sure things don't run too fast..
	 * On a 60 Mhz Pentium this takes 34 msec, so you would
	 * need 30 seconds to build a 1000 entry dictionary...
	 */

	for (i = 0; i < 1000; i++) {
	    md5_init(&ctx1);
	    if (i & 1) {
	        md5_update(&ctx1, pw, strlen(pw));
	    }
	    else {
	        md5_update(&ctx1, final, MD5_DIGESTSIZE);
	    }
	    if (i % 3) {
	        md5_update(&ctx1, sp, sl);
	    }

	    if (i % 7) {
	        md5_update(&ctx1, pw, strlen(pw));
	    }

	    if (i & 1) {
	        md5_update(&ctx1, final, MD5_DIGESTSIZE);
	    }
	    else {
	        md5_update(&ctx1, pw, strlen(pw));
	    }
	    md5_final(final,&ctx1);
	}


	p = passwd + strlen(passwd);

	l = (final[ 0]<<16) | (final[ 6]<<8) | final[12]; to64(p, l, 4); p += 4;
	l = (final[ 1]<<16) | (final[ 7]<<8) | final[13]; to64(p, l, 4); p += 4;
	l = (final[ 2]<<16) | (final[ 8]<<8) | final[14]; to64(p, l, 4); p += 4;
	l = (final[ 3]<<16) | (final[ 9]<<8) | final[15]; to64(p, l, 4); p += 4;
	l = (final[ 4]<<16) | (final[10]<<8) | final[ 5]; to64(p, l, 4); p += 4;
	l =                    final[11]                ; to64(p, l, 2); p += 2;
	*p = '\0';

	/*
	 * Don't leave anything around in vm they could use.
	 */
	memset(final, 0, sizeof(final));

	strcpy( result, passwd );

	return result;

}

char* sha1( char *clear )
{
	char *result;
	char out[35];

    int l;
    int len;
    sha1_ctx_t context;
    t_byte_t digest[SHA1_DIGESTSIZE];

	result = (char*)malloc(35*sizeof(char));

	len = strlen(clear);

    if (strncmp(clear, SHA1PW_ID, SHA1PW_IDLEN) == 0) {
	clear += SHA1PW_IDLEN;
    }

    sha1_init(&context);
    sha1_update(&context, clear, len);
    sha1_final(digest, &context);

    strncpy(out, SHA1PW_ID, SHA1PW_IDLEN + 1);

    /* SHA1 hash is always 20 chars */
    l = base64_encode_binary(out + SHA1PW_IDLEN, digest, sizeof(digest));
    out[l + SHA1PW_IDLEN] = '\0';

    /*
     * output of base64 encoded SHA1 is always 28 chars + SHA1PW_IDLEN
     */

    strcpy( result, out);

    return result;
}



void md5_init(md5_ctx * context)
{
	context->count[0] = context->count[1] = 0;
	/* Load magic initialization constants.
	 */
	context->state[0] = 0x67452301;
	context->state[1] = 0xefcdab89;
	context->state[2] = 0x98badcfe;
	context->state[3] = 0x10325476;
}

void md5_update(md5_ctx * context, const unsigned char *input,
			   unsigned int inputLen)
{
	unsigned int i, index, partLen;

	/* Compute number of bytes mod 64 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3F);

	/* Update number of bits */
	if ((context->count[0] += ((uint32) inputLen << 3))
		< ((uint32) inputLen << 3))
		context->count[1]++;
	context->count[1] += ((uint32) inputLen >> 29);

	partLen = 64 - index;

	/* Transform as many times as possible.
	 */
	if (inputLen >= partLen) {
		memcpy
			((unsigned char*) & context->buffer[index], (unsigned char*) input, partLen);
		md5_transform(context->state, context->buffer);

		for (i = partLen; i + 63 < inputLen; i += 64)
			md5_transform(context->state, &input[i]);

		index = 0;
	} else
		i = 0;

	/* Buffer remaining input */
	memcpy
		((unsigned char*) & context->buffer[index], (unsigned char*) & input[i],
		 inputLen - i);
}

void md5_final(unsigned char digest[16], md5_ctx * context)
{
	unsigned char bits[8];
	unsigned int index, padLen;

	/* Save number of bits */
	Encode(bits, context->count, 8);

	/* Pad out to 56 mod 64.
	 */
	index = (unsigned int) ((context->count[0] >> 3) & 0x3f);
	padLen = (index < 56) ? (56 - index) : (120 - index);
	md5_update(context, PADDING, padLen);

	/* Append length (before padding) */
	md5_update(context, bits, 8);

	/* Store state in digest */
	Encode(digest, context->state, 16);

	/* Zeroize sensitive information.
	 */
	memset((unsigned char*) context, 0, sizeof(*context));
}

static void md5_transform(uint32 state[4], const unsigned char block[64])
{
	uint32 a = state[0], b = state[1], c = state[2], d = state[3], x[16];

	Decode(x, block, 64);

	/* Round 1 */
	FF(a, b, c, d, x[0], S11, 0xd76aa478);	/* 1 */
	FF(d, a, b, c, x[1], S12, 0xe8c7b756);	/* 2 */
	FF(c, d, a, b, x[2], S13, 0x242070db);	/* 3 */
	FF(b, c, d, a, x[3], S14, 0xc1bdceee);	/* 4 */
	FF(a, b, c, d, x[4], S11, 0xf57c0faf);	/* 5 */
	FF(d, a, b, c, x[5], S12, 0x4787c62a);	/* 6 */
	FF(c, d, a, b, x[6], S13, 0xa8304613);	/* 7 */
	FF(b, c, d, a, x[7], S14, 0xfd469501);	/* 8 */
	FF(a, b, c, d, x[8], S11, 0x698098d8);	/* 9 */
	FF(d, a, b, c, x[9], S12, 0x8b44f7af);	/* 10 */
	FF(c, d, a, b, x[10], S13, 0xffff5bb1);		/* 11 */
	FF(b, c, d, a, x[11], S14, 0x895cd7be);		/* 12 */
	FF(a, b, c, d, x[12], S11, 0x6b901122);		/* 13 */
	FF(d, a, b, c, x[13], S12, 0xfd987193);		/* 14 */
	FF(c, d, a, b, x[14], S13, 0xa679438e);		/* 15 */
	FF(b, c, d, a, x[15], S14, 0x49b40821);		/* 16 */

	/* Round 2 */
	GG(a, b, c, d, x[1], S21, 0xf61e2562);	/* 17 */
	GG(d, a, b, c, x[6], S22, 0xc040b340);	/* 18 */
	GG(c, d, a, b, x[11], S23, 0x265e5a51);		/* 19 */
	GG(b, c, d, a, x[0], S24, 0xe9b6c7aa);	/* 20 */
	GG(a, b, c, d, x[5], S21, 0xd62f105d);	/* 21 */
	GG(d, a, b, c, x[10], S22, 0x2441453);	/* 22 */
	GG(c, d, a, b, x[15], S23, 0xd8a1e681);		/* 23 */
	GG(b, c, d, a, x[4], S24, 0xe7d3fbc8);	/* 24 */
	GG(a, b, c, d, x[9], S21, 0x21e1cde6);	/* 25 */
	GG(d, a, b, c, x[14], S22, 0xc33707d6);		/* 26 */
	GG(c, d, a, b, x[3], S23, 0xf4d50d87);	/* 27 */
	GG(b, c, d, a, x[8], S24, 0x455a14ed);	/* 28 */
	GG(a, b, c, d, x[13], S21, 0xa9e3e905);		/* 29 */
	GG(d, a, b, c, x[2], S22, 0xfcefa3f8);	/* 30 */
	GG(c, d, a, b, x[7], S23, 0x676f02d9);	/* 31 */
	GG(b, c, d, a, x[12], S24, 0x8d2a4c8a);		/* 32 */

	/* Round 3 */
	HH(a, b, c, d, x[5], S31, 0xfffa3942);	/* 33 */
	HH(d, a, b, c, x[8], S32, 0x8771f681);	/* 34 */
	HH(c, d, a, b, x[11], S33, 0x6d9d6122);		/* 35 */
	HH(b, c, d, a, x[14], S34, 0xfde5380c);		/* 36 */
	HH(a, b, c, d, x[1], S31, 0xa4beea44);	/* 37 */
	HH(d, a, b, c, x[4], S32, 0x4bdecfa9);	/* 38 */
	HH(c, d, a, b, x[7], S33, 0xf6bb4b60);	/* 39 */
	HH(b, c, d, a, x[10], S34, 0xbebfbc70);		/* 40 */
	HH(a, b, c, d, x[13], S31, 0x289b7ec6);		/* 41 */
	HH(d, a, b, c, x[0], S32, 0xeaa127fa);	/* 42 */
	HH(c, d, a, b, x[3], S33, 0xd4ef3085);	/* 43 */
	HH(b, c, d, a, x[6], S34, 0x4881d05);	/* 44 */
	HH(a, b, c, d, x[9], S31, 0xd9d4d039);	/* 45 */
	HH(d, a, b, c, x[12], S32, 0xe6db99e5);		/* 46 */
	HH(c, d, a, b, x[15], S33, 0x1fa27cf8);		/* 47 */
	HH(b, c, d, a, x[2], S34, 0xc4ac5665);	/* 48 */

	/* Round 4 */
	II(a, b, c, d, x[0], S41, 0xf4292244);	/* 49 */
	II(d, a, b, c, x[7], S42, 0x432aff97);	/* 50 */
	II(c, d, a, b, x[14], S43, 0xab9423a7);		/* 51 */
	II(b, c, d, a, x[5], S44, 0xfc93a039);	/* 52 */
	II(a, b, c, d, x[12], S41, 0x655b59c3);		/* 53 */
	II(d, a, b, c, x[3], S42, 0x8f0ccc92);	/* 54 */
	II(c, d, a, b, x[10], S43, 0xffeff47d);		/* 55 */
	II(b, c, d, a, x[1], S44, 0x85845dd1);	/* 56 */
	II(a, b, c, d, x[8], S41, 0x6fa87e4f);	/* 57 */
	II(d, a, b, c, x[15], S42, 0xfe2ce6e0);		/* 58 */
	II(c, d, a, b, x[6], S43, 0xa3014314);	/* 59 */
	II(b, c, d, a, x[13], S44, 0x4e0811a1);		/* 60 */
	II(a, b, c, d, x[4], S41, 0xf7537e82);	/* 61 */
	II(d, a, b, c, x[11], S42, 0xbd3af235);		/* 62 */
	II(c, d, a, b, x[2], S43, 0x2ad7d2bb);	/* 63 */
	II(b, c, d, a, x[9], S44, 0xeb86d391);	/* 64 */

	state[0] += a;
	state[1] += b;
	state[2] += c;
	state[3] += d;

	/* Zeroize sensitive information. */
	memset((unsigned char*) x, 0, sizeof(x));
}

static void Encode(unsigned char *output, uint32 *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4) {
		output[j] = (unsigned char) (input[i] & 0xff);
		output[j + 1] = (unsigned char) ((input[i] >> 8) & 0xff);
		output[j + 2] = (unsigned char) ((input[i] >> 16) & 0xff);
		output[j + 3] = (unsigned char) ((input[i] >> 24) & 0xff);
	}
}

static void Decode(uint32 *output, const unsigned char *input, unsigned int len)
{
	unsigned int i, j;

	for (i = 0, j = 0; j < len; i++, j += 4)
		output[i] = ((uint32) input[j]) | (((uint32) input[j + 1]) << 8) |
			(((uint32) input[j + 2]) << 16) | (((uint32) input[j + 3]) << 24);
}

static void sha_transform(sha1_ctx_t *sha_info)
{
    int i;
    t_uint32_t temp, A, B, C, D, E, W[80];

    for (i = 0; i < 16; ++i) {
	W[i] = sha_info->data[i];
    }
    for (i = 16; i < 80; ++i) {
	W[i] = W[i-3] ^ W[i-8] ^ W[i-14] ^ W[i-16];
#ifdef USE_MODIFIED_SHA
	W[i] = ROT32(W[i], 1);
#endif /* USE_MODIFIED_SHA */
    }
    A = sha_info->digest[0];
    B = sha_info->digest[1];
    C = sha_info->digest[2];
    D = sha_info->digest[3];
    E = sha_info->digest[4];
#ifdef UNROLL_LOOPS
    FUNC(1, 0);  FUNC(1, 1);  FUNC(1, 2);  FUNC(1, 3);  FUNC(1, 4);
    FUNC(1, 5);  FUNC(1, 6);  FUNC(1, 7);  FUNC(1, 8);  FUNC(1, 9);
    FUNC(1,10);  FUNC(1,11);  FUNC(1,12);  FUNC(1,13);  FUNC(1,14);
    FUNC(1,15);  FUNC(1,16);  FUNC(1,17);  FUNC(1,18);  FUNC(1,19);

    FUNC(2,20);  FUNC(2,21);  FUNC(2,22);  FUNC(2,23);  FUNC(2,24);
    FUNC(2,25);  FUNC(2,26);  FUNC(2,27);  FUNC(2,28);  FUNC(2,29);
    FUNC(2,30);  FUNC(2,31);  FUNC(2,32);  FUNC(2,33);  FUNC(2,34);
    FUNC(2,35);  FUNC(2,36);  FUNC(2,37);  FUNC(2,38);  FUNC(2,39);

    FUNC(3,40);  FUNC(3,41);  FUNC(3,42);  FUNC(3,43);  FUNC(3,44);
    FUNC(3,45);  FUNC(3,46);  FUNC(3,47);  FUNC(3,48);  FUNC(3,49);
    FUNC(3,50);  FUNC(3,51);  FUNC(3,52);  FUNC(3,53);  FUNC(3,54);
    FUNC(3,55);  FUNC(3,56);  FUNC(3,57);  FUNC(3,58);  FUNC(3,59);

    FUNC(4,60);  FUNC(4,61);  FUNC(4,62);  FUNC(4,63);  FUNC(4,64);
    FUNC(4,65);  FUNC(4,66);  FUNC(4,67);  FUNC(4,68);  FUNC(4,69);
    FUNC(4,70);  FUNC(4,71);  FUNC(4,72);  FUNC(4,73);  FUNC(4,74);
    FUNC(4,75);  FUNC(4,76);  FUNC(4,77);  FUNC(4,78);  FUNC(4,79);
#else /* !UNROLL_LOOPS */
    for (i = 0; i < 20; ++i) {
	FUNC(1,i);
    }
    for (i = 20; i < 40; ++i) {
	FUNC(2,i);
    }
    for (i = 40; i < 60; ++i) {
	FUNC(3,i);
    }
    for (i = 60; i < 80; ++i) {
	FUNC(4,i);
    }
#endif /* !UNROLL_LOOPS */
    sha_info->digest[0] += A;
    sha_info->digest[1] += B;
    sha_info->digest[2] += C;
    sha_info->digest[3] += D;
    sha_info->digest[4] += E;
}

union endianTest {
    long Long;
    char Char[sizeof(long)];
};

static char isLittleEndian(void)
{
    static union endianTest u;
    u.Long = 1;
    return (u.Char[0] == 1);
}

/* change endianness of data */

/* count is the number of bytes to do an endian flip */
static void maybe_byte_reverse(t_uint32_t *buffer, int count)
{
    int i;
    t_byte_t ct[4], *cp;

    if (isLittleEndian()) {	/* do the swap only if it is little endian */
	count /= sizeof(t_uint32_t);
	cp = (t_byte_t *) buffer;
	for (i = 0; i < count; ++i) {
	    ct[0] = cp[0];
	    ct[1] = cp[1];
	    ct[2] = cp[2];
	    ct[3] = cp[3];
	    cp[0] = ct[3];
	    cp[1] = ct[2];
	    cp[2] = ct[1];
	    cp[3] = ct[0];
	    cp += sizeof(t_uint32_t);
	}
    }
}

/* initialize the SHA digest */

void sha1_init(sha1_ctx_t *sha_info)
{
    sha_info->digest[0] = 0x67452301L;
    sha_info->digest[1] = 0xefcdab89L;
    sha_info->digest[2] = 0x98badcfeL;
    sha_info->digest[3] = 0x10325476L;
    sha_info->digest[4] = 0xc3d2e1f0L;
    sha_info->count_lo = 0L;
    sha_info->count_hi = 0L;
    sha_info->local = 0;
}

/* update the SHA digest */

void sha1_update_binary(sha1_ctx_t *sha_info,
                                     const unsigned char *buffer,
                                     unsigned int count)
{
    unsigned int i;

    if ((sha_info->count_lo + ((t_uint32_t) count << 3)) < sha_info->count_lo) {
	++sha_info->count_hi;
    }
    sha_info->count_lo += (t_uint32_t) count << 3;
    sha_info->count_hi += (t_uint32_t) count >> 29;
    if (sha_info->local) {
	i = SHA_BLOCKSIZE - sha_info->local;
	if (i > count) {
	    i = count;
	}
	memcpy(((t_byte_t *) sha_info->data) + sha_info->local, buffer, i);
	count -= i;
	buffer += i;
	sha_info->local += i;
	if (sha_info->local == SHA_BLOCKSIZE) {
	    maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	    sha_transform(sha_info);
	}
	else {
	    return;
	}
    }
    while (count >= SHA_BLOCKSIZE) {
	memcpy(sha_info->data, buffer, SHA_BLOCKSIZE);
	buffer += SHA_BLOCKSIZE;
	count -= SHA_BLOCKSIZE;
	maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	sha_transform(sha_info);
    }
    memcpy(sha_info->data, buffer, count);
    sha_info->local = count;
}

void sha1_update(sha1_ctx_t *sha_info, const char *buf,
                              unsigned int count)
{

    sha1_update_binary(sha_info, (const unsigned char *) buf, count);

}

/* finish computing the SHA digest */

void sha1_final(unsigned char digest[SHA1_DIGESTSIZE],
                             sha1_ctx_t *sha_info)
{
    int count, i, j;
    t_uint32_t lo_bit_count, hi_bit_count, k;

    lo_bit_count = sha_info->count_lo;
    hi_bit_count = sha_info->count_hi;
    count = (int) ((lo_bit_count >> 3) & 0x3f);
    ((t_byte_t *) sha_info->data)[count++] = 0x80;
    if (count > SHA_BLOCKSIZE - 8) {
	memset(((t_byte_t *) sha_info->data) + count, 0, SHA_BLOCKSIZE - count);
	maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
	sha_transform(sha_info);
	memset((t_byte_t *) sha_info->data, 0, SHA_BLOCKSIZE - 8);
    }
    else {
	memset(((t_byte_t *) sha_info->data) + count, 0,
	       SHA_BLOCKSIZE - 8 - count);
    }
    maybe_byte_reverse(sha_info->data, SHA_BLOCKSIZE);
    sha_info->data[14] = hi_bit_count;
    sha_info->data[15] = lo_bit_count;
    sha_transform(sha_info);

    for (i = 0, j = 0; j < SHA1_DIGESTSIZE; i++) {
	k = sha_info->digest[i];
	digest[j++] = (unsigned char) ((k >> 24) & 0xff);
	digest[j++] = (unsigned char) ((k >> 16) & 0xff);
	digest[j++] = (unsigned char) ((k >> 8) & 0xff);
	digest[j++] = (unsigned char) (k & 0xff);
    }
}

int base64_decode_len(const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);

    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    return nbytesdecoded + 1;
}

int base64_decode(char *bufplain, const char *bufcoded)
{
    int len;

    len = base64_decode_binary((unsigned char *) bufplain, bufcoded);
    bufplain[len] = '\0';
    return len;
}

int base64_decode_binary(unsigned char *bufplain,
				   const char *bufcoded)
{
    int nbytesdecoded;
    register const unsigned char *bufin;
    register unsigned char *bufout;
    register int nprbytes;

    bufin = (const unsigned char *) bufcoded;
    while (pr2six[*(bufin++)] <= 63);
    nprbytes = (bufin - (const unsigned char *) bufcoded) - 1;
    nbytesdecoded = ((nprbytes + 3) / 4) * 3;

    bufout = (unsigned char *) bufplain;
    bufin = (const unsigned char *) bufcoded;

    while (nprbytes > 4) {
	*(bufout++) =
	    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
	bufin += 4;
	nprbytes -= 4;
    }

    /* Note: (nprbytes == 1) would be an error, so just ingore that case */
    if (nprbytes > 1) {
	*(bufout++) =
	    (unsigned char) (pr2six[*bufin] << 2 | pr2six[bufin[1]] >> 4);
    }
    if (nprbytes > 2) {
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[1]] << 4 | pr2six[bufin[2]] >> 2);
    }
    if (nprbytes > 3) {
	*(bufout++) =
	    (unsigned char) (pr2six[bufin[2]] << 6 | pr2six[bufin[3]]);
    }

    nbytesdecoded -= (4 - nprbytes) & 3;
    return nbytesdecoded;
}

int base64_encode_len(int len)
{
    return ((len + 2) / 3 * 4) + 1;
}

int base64_encode(char *encoded, const char *string, int len)
{
    return base64_encode_binary(encoded, (const unsigned char *) string, len);
}

int base64_encode_binary(char *encoded, const unsigned char *string, int len)
{
    int i;
    char *p;

    p = encoded;
    for (i = 0; i < len - 2; i += 3) {
	*p++ = basis_64[(string[i] >> 2) & 0x3F];
	*p++ = basis_64[((string[i] & 0x3) << 4) |
	                ((int) (string[i + 1] & 0xF0) >> 4)];
	*p++ = basis_64[((string[i + 1] & 0xF) << 2) |
	                ((int) (string[i + 2] & 0xC0) >> 6)];
	*p++ = basis_64[string[i + 2] & 0x3F];
    }
    if (i < len) {
	*p++ = basis_64[(string[i] >> 2) & 0x3F];
	if (i == (len - 1)) {
	    *p++ = basis_64[((string[i] & 0x3) << 4)];
	    *p++ = '=';
	}
	else {
	    *p++ = basis_64[((string[i] & 0x3) << 4) |
	                    ((int) (string[i + 1] & 0xF0) >> 4)];
	    *p++ = basis_64[((string[i + 1] & 0xF) << 2)];
	}
	*p++ = '=';
    }

    *p++ = '\0';
    return p - encoded;
}


#endif
