/*
 * FIPS 180-2 SHA-224/256/384/512 implementation
 * Last update: 02/02/2007
 * Issue date:  04/30/2005
 *
 * Copyright (C) 2013, Con Kolivas <kernel@kolivas.org>
 * Copyright (C) 2005, 2007 Olivier Gay <olivier.gay@a3.epfl.ch>
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "cgminer.h"

#define UNPACK32(x, str)                      \
{                                             \
    *((str) + 3) = (uint8_t) ((x)      );       \
    *((str) + 2) = (uint8_t) ((x) >>  8);       \
    *((str) + 1) = (uint8_t) ((x) >> 16);       \
    *((str) + 0) = (uint8_t) ((x) >> 24);       \
}

#define PACK32(str, x)                        \
{                                             \
    *(x) =   ((uint32_t) *((str) + 3)      )    \
           | ((uint32_t) *((str) + 2) <<  8)    \
           | ((uint32_t) *((str) + 1) << 16)    \
           | ((uint32_t) *((str) + 0) << 24);   \
}

#define SHA256_SCR(i)                         \
{                                             \
    w[i] =  SHA256_F4(w[i -  2]) + w[i -  7]  \
          + SHA256_F3(w[i - 15]) + w[i - 16]; \
}

uint32_t sha256_h0[8] =
            {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
             0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19};

uint32_t sha256_k[64] =
            {0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
             0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
             0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
             0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
             0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
             0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
             0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
             0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
             0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
             0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
             0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
             0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
             0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
             0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
             0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
             0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/* SHA-256 functions */

void sha256_transf(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int block_nb)
{
    uint32_t w[64];
    uint32_t wv[8];
    uint32_t t1, t2;
    const unsigned char *sub_block;
    int i;

    int j;

    for (i = 0; i < (int) block_nb; i++) {
		printf("sha256_transf: block_nb = %u, round = %u\n", block_nb, i);
        sub_block = message + (i << 6); //ptr to start of each block

        for (j = 0; j < 16; j++) {
            PACK32(&sub_block[j << 2], &w[j]);
        }

        for (j = 16; j < 64; j++) {
            SHA256_SCR(j);
        }

        for (j = 0; j < 8; j++) {
            wv[j] = ctx->h[j];
        }

        for (j = 0; j < 64; j++) {
            t1 = wv[7] + SHA256_F2(wv[4]) + CH(wv[4], wv[5], wv[6])
                + sha256_k[j] + w[j];
            t2 = SHA256_F1(wv[0]) + MAJ(wv[0], wv[1], wv[2]);
            wv[7] = wv[6];
            wv[6] = wv[5];
            wv[5] = wv[4];
            wv[4] = wv[3] + t1;
            wv[3] = wv[2];
            wv[2] = wv[1];
            wv[1] = wv[0];
            wv[0] = t1 + t2;
        }

        for (j = 0; j < 8; j++) {
            ctx->h[j] += wv[j];
        }
    }
}

void sha256(const unsigned char *message, unsigned int len, unsigned char *digest)
{
    sha256_ctx ctx;

    sha256_init(&ctx);
    sha256_update(&ctx, message, len); //len in bytes, NOT bits!!
    sha256_final(&ctx, digest);
}

//use `cgminer ""` to test empty string
//spec always in bits, C always in bytes!!!!!!
int main(int argc, char **argv)
{
	unsigned char digest[32], i;
	unsigned char ottf[4] = {0x1, 0x2, 0x3, 0x4};
	unsigned int x;

	for (i=0; i<4; i++)
		printf("0x%x ", ottf[i]);

	PACK32(ottf,&x);
	printf("\n0x%08x\n", x); //0x01020304

	UNPACK32(x,digest);
	for (i=0; i<4; i++)
		printf("0x%x ", digest[i]); //0x1 0x2 0x3 0x4
	printf("\n");
	return 0;

	printf("%s %lu\n", argv[1], strlen(argv[1]));
	sha256(argv[1], strlen(argv[1]), digest);
	for (i=0; i<32; i++)
	{
		printf("%x", digest[i]);
	}
	printf("\n");
	return 0;
}

void sha256_init(sha256_ctx *ctx)
{
    int i;
    for (i = 0; i < 8; i++) {
        ctx->h[i] = sha256_h0[i];
    }

    ctx->len = 0;
    ctx->tot_len = 0;
}

//len in bytes, NOT bits!!
void sha256_update(sha256_ctx *ctx, const unsigned char *message,
                   unsigned int len)
{
    unsigned int block_nb;
    unsigned int new_len, rem_len, tmp_len; //rem = remaining
    const unsigned char *shifted_message;

    tmp_len = SHA256_BLOCK_SIZE /*64*/ - ctx->len;
	//ctx->len always 0, no?
	//then if len < 64, rem_len = len, else rem_len = 64
	if (len < tmp_len)
	{
		printf("len = rem_len = %u < tmp_len = %u\n", len, tmp_len);
		rem_len = len;
	}
	else
	{
		printf("len = %u >= tmp_len = rem_len = %u\n", len, tmp_len);
		rem_len = tmp_len;
	}
	printf("ctx->len = %u\n", ctx->len /* 0 */);

    memcpy(&ctx->block[ctx->len], message, rem_len); //memcpy dst src len
    printf("message = %s\n", message);
    printf("&ctx->block[%u] = %s\n", ctx->len, &ctx->block[ctx->len]);

    if (ctx->len /* 0 */ + len < SHA256_BLOCK_SIZE /*64*/) {
        ctx->len += len;
		printf("len < 64 so just do sha256_final\n");
        return;
    }

	//len > SHA256_BLOCK_SIZE /*64*/
    new_len = len - rem_len /*64*/;
    block_nb = new_len / SHA256_BLOCK_SIZE /*64*/; //can b 0
	printf("new_len = %u, block_nb = %u\n", new_len, block_nb);

    shifted_message = message + rem_len /*64*/;

    printf("ctx->block = %s\n", ctx->block);
    sha256_transf(ctx, ctx->block, 1); //ctk->block = message, i.e. beginning of msg

    printf("sha256_updt: block_nb = %u\n", block_nb);
	//if block_nb = 0, sha256_transf just returns
	//eg only 2 blocks, 1st n last, i.e.
	//do 1st here in sha256_transf above
	//do nothing in blo sha256_transf
	//do last in sha256_final
    sha256_transf(ctx, shifted_message, block_nb);

    rem_len = new_len % SHA256_BLOCK_SIZE /*64*/;
	printf("rem_len = %u\n", rem_len);

	//block_nb << 6 = block_nb * 64
    memcpy(ctx->block, &shifted_message[block_nb << 6], rem_len); //copy last/end of msg, rem_len that has yet 2b processed
    printf("&shifted_message[%u or %u] = %s\n", block_nb * 64, block_nb << 6, &shifted_message[block_nb << 6]);
    printf("ctx->block = %s\n", ctx->block);

    ctx->len = rem_len;
    ctx->tot_len += (block_nb + 1) << 6;
}

void sha256_final(sha256_ctx *ctx, unsigned char *digest)
{
    unsigned int block_nb;
    unsigned int pm_len;
    unsigned int len_b;

    int i;

	printf("sha256_final\n");

	//Section 5.1.1
	//Suppose that the length of the message, M, is L bits. Append the bit "1" to the end of the message, followed by k zero bits, 
	//where k is the smallest, non-negative (can b 0?) solution to the equation L + 1 + k = 448 mod 512. Then append the 64-bit block that is 
	//equal to the number L expressed using a binary representation.
	//For example, the (8-bit ASCII) message "abc" has length 8x3 = 24, so the message is padded with a one bit, then 448 - (24 + 1) = 423 
	//zero bits, and then the message length, to become the 512-bit padded message

	//so u cant just pad 1 bit in C cos min is a byte (char), so da min is 1 byte (1000, ie k=3), plus 8 bytes (64 bits) to denote L, = 9 bytes 
	//so if rem_len (i.e. ctx->len) > 55 bytes, block_nb = 2, else block_nb = 1
	//55 + 9 = 64 bytes

    block_nb = (1 + ((SHA256_BLOCK_SIZE /*64*/ - 9 /* = 55 */)
                     < (ctx->len % SHA256_BLOCK_SIZE /*64*/)));
    printf("sha256_final: block_nb = %u\n", block_nb);

	//len_b = len_bits
    len_b = (ctx->tot_len + ctx->len) << 3 /* x8 */;
	printf("len_b = %u 0x%08x\n", len_b, len_b);
    pm_len = block_nb << 6; //=64 OR 128
	printf("pm_len = %u, ctx->len = %u\n", pm_len, ctx->len);

    memset(ctx->block + ctx->len, 0, pm_len - ctx->len); //set end o msg to all 0s, whether it's 1 or 2 blocks
	printf("\n");
	for (i=0; i<128; i++)
	{
		//printf("%d:%x ", i, ctx->block[i]);
		printf("%02x ", ctx->block[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n\n");
    ctx->block[ctx->len] = 0x80; //set 1 immediately after msg
	for (i=0; i<128; i++)
	{
		//printf("%d:%x ", i, ctx->block[i]);
		printf("%02x ", ctx->block[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n\n");
    UNPACK32(len_b, ctx->block + pm_len - 4); //set msg len in last 32b o msg
	//according to spec, should b last 64b o msg, but this uses UNPACK32
	//so assume msg len will NOT > 2^32?
	for (i=0; i<128; i++)
	{
		//printf("%d:%x ", i, ctx->block[i]);
		printf("%02x ", ctx->block[i]);
		if ((i + 1) % 16 == 0) printf("\n");
	}
	printf("\n\n");

    sha256_transf(ctx, ctx->block, block_nb);

    for (i = 0 ; i < 8; i++) {
        UNPACK32(ctx->h[i], &digest[i << 2]); //<< 2 = x4
    }
}
