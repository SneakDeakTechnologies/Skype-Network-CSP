#ifndef _sha1_h_
#define _sha1_h_

#include "../crypto.h"

#define SHA1_HASH_BITS			160
#define SHA1_BLOCK_BITS			512

#define SHA1_HASH_WORDS			((SHA1_HASH_BITS + 31) / 32)
#define SHA1_BLOCK_WORDS		((SHA1_BLOCK_BITS + 31) / 32)
#define SHA1_HASH_BYTES			(SHA1_HASH_WORDS * 4)
#define SHA1_BLOCK_BYTES		(SHA1_BLOCK_WORDS * 4)

#define SHA1_v					1

#define SHA1_LAST_BLOCK_BITS	(SHA1_BLOCK_BITS - 64)
#define SHA1_LAST_BLOCK_WORDS	((SHA1_LAST_BLOCK_BITS + 31) / 32)
#define SHA1_LAST_BLOCK_BYTES	(SHA1_LAST_BLOCK_WORDS * 4)

#define SHA1_expand(i)			blk[i] = rotl32 (blk[i-3] ^ blk[i-8] ^ blk[i-14] ^ blk[i-16], SHA1_v)
#define SHA1_ADD(a,b,c,d,e)		(SHA1->hash[0] += a, SHA1->hash[1] += b, SHA1->hash[2] += c, SHA1->hash[3] += d, SHA1->hash[4] += e)

#define SHA1_R0(v,w,x,y,z,i)	(z += blk[i] + 0x5A827999 + rotl32 (v, 5) + ((w&(x^y))^y)    , w = rotl32 (w, 30))
#define SHA1_R1(v,w,x,y,z,i)	(z += blk[i] + 0x6ED9EBA1 + rotl32 (v, 5) + (w^x^y)          , w = rotl32 (w, 30))
#define SHA1_R2(v,w,x,y,z,i)	(z += blk[i] + 0x8F1BBCDC + rotl32 (v, 5) + (((w|x)&y)|(w&x)), w = rotl32 (w, 30))
#define SHA1_R3(v,w,x,y,z,i)	(z += blk[i] + 0xCA62C1D6 + rotl32 (v, 5) + (w^x^y)          , w = rotl32 (w, 30))

typedef struct _SHA1_state
{
	u32			hash[SHA1_HASH_WORDS];
	u32			pos;
	u32			bits[2];
	u32			data[SHA1_BLOCK_WORDS];
} SHA1_state;

#define SHA1_INIT { {0x67452301UL, 0xEFCDAB89UL, 0x98BADCFEUL, 0x10325476UL, 0xC3D2E1F0UL}, 0, {0} }

static void SHA1_init(SHA1_state* SHA1_context) { SHA1_context->hash[0] = 0x67452301UL; SHA1_context->hash[1] = 0xEFCDAB89UL; SHA1_context->hash[2] = 0x98BADCFEUL; SHA1_context->hash[3] = 0x10325476UL; SHA1_context->hash[4] = 0xC3D2E1F0UL; SHA1_context->pos = 0; SHA1_context->bits[0] = 0; SHA1_context->bits[1] = 0; }
extern void SHA1_update(SHA1_state* SHA1_context, const void* data, u32 bytes);

extern void SHA1_end(SHA1_state* SHA1_context);
extern void SHA1_hash(const void* data, u32 bytes, void* hash);

#endif
