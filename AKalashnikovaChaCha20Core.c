#include <assert.h>
#include <inttypes.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include "minunit.h"

struct chacha20_context
{
    uint32_t keystream32[16];
    size_t position;

    uint8_t key[32];
    uint8_t nonce[12];
    uint64_t counter;

    uint32_t state[16];
} cc20ctx = { .position = -1 };

static inline uint32_t rotl32(uint32_t x, int n) {
    // http://blog.regehr.org/archives/1063
    return x << n | (x >> (-n & 31));
}

// https://tools.ietf.org/html/rfc7539#section-2.1
static void chacha20_quarterround(uint32_t *x, int a, int b, int c, int d) {
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a], 16);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c], 12);
    x[a] += x[b]; x[d] = rotl32(x[d] ^ x[a],  8);
    x[c] += x[d]; x[b] = rotl32(x[b] ^ x[c],  7);
}

static inline void u32t8le(uint32_t v, uint8_t p[4]) {
    p[0] = v & 0xff;
    p[1] = (v >> 8) & 0xff;   // (v & 0x0000ff00) >> 8
    p[2] = (v >> 16) & 0xff;  // (v & 0x00ff0000) >> 16
    p[3] = (v >> 24) & 0xff;  // (v & 0xff000000) >> 24
}

static inline uint32_t u8t32le(uint8_t p[4]) {
    uint32_t value = p[3];

    value = (value << 8) | p[2];
    value = (value << 8) | p[1];
    value = (value << 8) | p[0];

    return value;
}

/*static uint32_t pack4(const uint8_t *a)
{
    uint32_t res = 0;
    res |= (uint32_t)a[0] << 0 * 8;
    res |= (uint32_t)a[1] << 1 * 8;
    res |= (uint32_t)a[2] << 2 * 8;
    res |= (uint32_t)a[3] << 3 * 8;
    return res;
}*/

static void chacha20_serialize(uint32_t in[16], uint8_t output[64]) {
    int i;
    for (i = 0; i < 16; i++) {
        u32t8le(in[i], output + (i << 2));
    }
}

static void chacha20_init_block(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[])
{
    memcpy(ctx->key, key, sizeof(ctx->key));
    memcpy(ctx->nonce, nonce, sizeof(ctx->nonce));

    // refer: https://dxr.mozilla.org/mozilla-beta/source/security/nss/lib/freebl/chacha20.c
    // convert magic number to string: "expand 32-byte k"
    ctx->state[0] = 0x61707865;
    ctx->state[1] = 0x3320646e;
    ctx->state[2] = 0x79622d32;
    ctx->state[3] = 0x6b206574;
    ctx->state[4] = u8t32le(key + 0 * 4);
    ctx->state[5] = u8t32le(key + 1 * 4);
    ctx->state[6] = u8t32le(key + 2 * 4);
    ctx->state[7] = u8t32le(key + 3 * 4);
    ctx->state[8] = u8t32le(key + 4 * 4);
    ctx->state[9] = u8t32le(key + 5 * 4);
    ctx->state[10] = u8t32le(key + 6 * 4);
    ctx->state[11] = u8t32le(key + 7 * 4);
    // 64 bit counter initialized to zero by default.
    ctx->state[12] = 0;
    ctx->state[13] = u8t32le(nonce + 0 * 4);
    ctx->state[14] = u8t32le(nonce + 1 * 4);
    ctx->state[15] = u8t32le(nonce + 2 * 4);
}

static void chacha20_block_set_counter(struct chacha20_context *ctx, uint64_t counter)
{
    ctx->state[12] = (uint32_t)counter;
    ctx->state[13] = u8t32le(ctx->nonce + 0 * 4) + (uint32_t)(counter >> 32);
}

static void chacha20_block_next(struct chacha20_context *ctx) {
    memcpy(ctx->keystream32, ctx->state, sizeof(uint32_t) * 16);
    for (int i = 20; i > 0; i -= 2) {      // 20 = num_rounds
        chacha20_quarterround(ctx->keystream32, 0, 4,  8, 12);
        chacha20_quarterround(ctx->keystream32, 1, 5,  9, 13);
        chacha20_quarterround(ctx->keystream32, 2, 6, 10, 14);
        chacha20_quarterround(ctx->keystream32, 3, 7, 11, 15);
        chacha20_quarterround(ctx->keystream32, 0, 5, 10, 15);
        chacha20_quarterround(ctx->keystream32, 1, 6, 11, 12);
        chacha20_quarterround(ctx->keystream32, 2, 7,  8, 13);
        chacha20_quarterround(ctx->keystream32, 3, 4,  9, 14);
    }
    for (int i = 0; i < 16; i++) ctx->keystream32[i] += ctx->state[i];

    uint32_t *counter = ctx->state + 12;
    counter[0]++;
    if (0 == counter[0])
    {
        // from https://github.com/Ginurx/chacha20-c/blob/master/chacha20.c
        // wrap around occured, increment higher 32 bits of counter
        counter[1]++;
        // Limited to 2^64 blocks of 64 bytes each.
        // If you want to process more than 1180591620717411303424 bytes
        // you have other problems.
        // We could keep counting with counter[2] and counter[3] (nonce),
        // but then we risk reusing the nonce which is very bad.
        assert(0 != counter[1]);
    }
}

void chacha20_init_context(struct chacha20_context *ctx, uint8_t key[], uint8_t nonce[], uint64_t counter)
{
    memset(ctx, 0, sizeof(struct chacha20_context));

    chacha20_init_block(ctx, key, nonce);
    chacha20_block_set_counter(ctx, counter);

    ctx->counter = counter;
    ctx->position = 64;
}

// from https://github.com/shiffthq/chacha20/blob/master/test/chacha20_test.c
MU_TEST(u32t8le_test) {
    uint32_t value = 0x01020304; //  little-endian order: the lowest 8 bits come first, at the smallest address
    uint8_t p[4]; // { 0x04, 0x03, 0x02, 0x01 }

    u32t8le(value, p);

    mu_check(p[0] == 0x04);
    mu_check(p[1] == 0x03);
    mu_check(p[2] == 0x02);
    mu_check(p[3] == 0x01);
}

MU_TEST(u8t32le_test) {
    uint32_t value =  0x01020304; //  little-endian order: the lowest 8 bits come first, at the smallest address
    uint8_t p[4] = { 0x04, 0x03, 0x02, 0x01 };

    mu_check(u8t32le(p) == value);
}

MU_TEST(rotl32_test) {
    mu_check(rotl32(0x01020304, 8) == 0x02030401);
}

// https://tools.ietf.org/html/rfc7539#section-2.1.1
MU_TEST(chacha20_quarterround_test_1) {
    int i;
    uint32_t before[] = { 0x11111111, 0x01020304, 0x9b8d6f43, 0x01234567 };
    uint32_t after[] = { 0xea2a92f4, 0xcb1cf8ce, 0x4581472e, 0x5881c4bb };

    chacha20_quarterround(before, 0, 1, 2, 3);

    for (i = 0; i < 4; i++) {
        mu_check(before[i] == after[i]);
    }
}

// https://tools.ietf.org/html/rfc7539#section-2.2.1
MU_TEST(chacha20_quarterround_test_2) {
    int i;
    uint32_t before[] = {
        0x879531e0, 0xc5ecf37d, 0x516461b1, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0x2a5f714c,
        0x53372767, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0x3d631689, 0x2098d9d6, 0x91dbd320
    };
    uint32_t after[] = {
        0x879531e0, 0xc5ecf37d, 0xbdb886dc, 0xc9a62f8a,
        0x44c20ef3, 0x3390af7f, 0xd9fc690b, 0xcfacafd2,
        0xe46bea80, 0xb00a5631, 0x974c541a, 0x359e9963,
        0x5c971061, 0xccc07c79, 0x2098d9d6, 0x91dbd320
    };

    chacha20_quarterround(before, 2, 7, 8, 13);

    for (i = 0; i < 16; i++) {
        mu_check(before[i] == after[i]);
    }
}

MU_TEST(chacha20_serialize_test) {
    int i;
    uint32_t input[16] = {
        0xe4e7f110, 0x15593bd1, 0x1fdd0f50, 0xc47120a3,
        0xc7f4d1c7, 0x0368c033, 0x9aaa2204, 0x4e6cd4c3,
        0x466482d2, 0x09aa9f07, 0x05d7c214, 0xa2028bd9,
        0xd19c12b5, 0xb94e16de, 0xe883d0cb, 0x4e3c50a2
    };

    uint8_t expect[64] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e,
    };
    uint8_t output[64];

    chacha20_serialize(input, output);

    for (i = 0; i < 64; i++) {
        mu_check(output[i] == expect[i]);
    }
}

// https://tools.ietf.org/html/rfc7539#section-2.3.2
MU_TEST(chacha20_block_test) {
    int i;
    uint32_t initial_state[]  = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000
    };
    for (i = 0; i < 16; i++) {
        cc20ctx.state[i] = initial_state[i];
    }

    uint8_t expect[] = {
        0x10, 0xf1, 0xe7, 0xe4, 0xd1, 0x3b, 0x59, 0x15, 0x50, 0x0f, 0xdd, 0x1f, 0xa3, 0x20, 0x71, 0xc4,
        0xc7, 0xd1, 0xf4, 0xc7, 0x33, 0xc0, 0x68, 0x03, 0x04, 0x22, 0xaa, 0x9a, 0xc3, 0xd4, 0x6c, 0x4e,
        0xd2, 0x82, 0x64, 0x46, 0x07, 0x9f, 0xaa, 0x09, 0x14, 0xc2, 0xd7, 0x05, 0xd9, 0x8b, 0x02, 0xa2,
        0xb5, 0x12, 0x9c, 0xd1, 0xde, 0x16, 0x4e, 0xb9, 0xcb, 0xd0, 0x83, 0xe8, 0xa2, 0x50, 0x3c, 0x4e
    };

    chacha20_block_next(&cc20ctx);

    uint8_t block[64];
    chacha20_serialize(cc20ctx.keystream32, block);

    for (i = 0; i < 16; i++) {
        mu_check(block[i] == expect[i]);
    }
}

// https://tools.ietf.org/html/rfc7539#section-2.3.2
MU_TEST(chacha20_init_state_test) {
    int i;

    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    uint32_t expect[16] = {
        0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
        0x03020100, 0x07060504, 0x0b0a0908, 0x0f0e0d0c,
        0x13121110, 0x17161514, 0x1b1a1918, 0x1f1e1d1c,
        0x00000001, 0x09000000, 0x4a000000, 0x00000000
    };

    chacha20_init_context(&cc20ctx, key, nonce, 1);

    for (i = 0; i < 16; i++) {
        mu_check(cc20ctx.state[i] == expect[i]);
    }
}

// https://tools.ietf.org/html/rfc7539#section-2.4.2
MU_TEST(chacha20_xor_test) {
    int i, j;

    uint8_t key[] = {
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13,
        0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b,
        0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t nonce[] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };

    uint8_t input[114] = {
        0x4c, 0x61, 0x64, 0x69, 0x65, 0x73, 0x20, 0x61, 0x6e, 0x64, 0x20, 0x47, 0x65, 0x6e, 0x74, 0x6c,
        0x65, 0x6d, 0x65, 0x6e, 0x20, 0x6f, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x63, 0x6c, 0x61, 0x73,
        0x73, 0x20, 0x6f, 0x66, 0x20, 0x27, 0x39, 0x39, 0x3a, 0x20, 0x49, 0x66, 0x20, 0x49, 0x20, 0x63,
        0x6f, 0x75, 0x6c, 0x64, 0x20, 0x6f, 0x66, 0x66, 0x65, 0x72, 0x20, 0x79, 0x6f, 0x75, 0x20, 0x6f,
        0x6e, 0x6c, 0x79, 0x20, 0x6f, 0x6e, 0x65, 0x20, 0x74, 0x69, 0x70, 0x20, 0x66, 0x6f, 0x72, 0x20,
        0x74, 0x68, 0x65, 0x20, 0x66, 0x75, 0x74, 0x75, 0x72, 0x65, 0x2c, 0x20, 0x73, 0x75, 0x6e, 0x73,
        0x63, 0x72, 0x65, 0x65, 0x6e, 0x20, 0x77, 0x6f, 0x75, 0x6c, 0x64, 0x20, 0x62, 0x65, 0x20, 0x69,
        0x74, 0x2e
    };

    uint8_t expect[114] = {
        0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81,
        0xe9, 0x7e, 0x7a, 0xec, 0x1d, 0x43, 0x60, 0xc2, 0x0a, 0x27, 0xaf, 0xcc, 0xfd, 0x9f, 0xae, 0x0b,
        0xf9, 0x1b, 0x65, 0xc5, 0x52, 0x47, 0x33, 0xab, 0x8f, 0x59, 0x3d, 0xab, 0xcd, 0x62, 0xb3, 0x57,
        0x16, 0x39, 0xd6, 0x24, 0xe6, 0x51, 0x52, 0xab, 0x8f, 0x53, 0x0c, 0x35, 0x9f, 0x08, 0x61, 0xd8,
        0x07, 0xca, 0x0d, 0xbf, 0x50, 0x0d, 0x6a, 0x61, 0x56, 0xa3, 0x8e, 0x08, 0x8a, 0x22, 0xb6, 0x5e,
        0x52, 0xbc, 0x51, 0x4d, 0x16, 0xcc, 0xf8, 0x06, 0x81, 0x8c, 0xe9, 0x1a, 0xb7, 0x79, 0x37, 0x36,
        0x5a, 0xf9, 0x0b, 0xbf, 0x74, 0xa3, 0x5b, 0xe6, 0xb4, 0x0b, 0x8e, 0xed, 0xf2, 0x78, 0x5e, 0x42,
        0x87, 0x4d
    };

    uint8_t output[115];
    memset(output, 0, 115);
    output[114] = 0xff; // this should not be changed in the end

    chacha20_init_context(&cc20ctx, key, nonce, 1);

    for (i = 0; i < 114; i += 64) {
        chacha20_block_next(&cc20ctx);

        //uint8_t tmp_block[64];
        //chacha20_serialize(cc20ctx.keystream32, tmp_block);
        uint8_t *tmp_block = (uint8_t *) cc20ctx.keystream32;

        for (j = i; j < i + 64; j++) {
            if (j >= 114) {
                break;
            }
            output[j] = input[j] ^ tmp_block[j - i];
        }
    }

    for (i = 0; i < 114; i++) {
        mu_check(output[i] == expect[i]);
    }

    mu_check(output[114] == 0xff);
}

void chacha20_xor(struct chacha20_context *ctx, uint8_t *bytes, size_t n_bytes)
{
    uint8_t *keystream8 = (uint8_t*)ctx->keystream32;
    for (size_t i = 0; i < n_bytes; i++)
    {
        if (ctx->position >= 64)
        {
            chacha20_block_next(ctx);
            ctx->position = 0;
        }
        bytes[i] ^= keystream8[ctx->position];
        ctx->position++;
    }
}

// Unique primes numbers
/*  0x0f6b75ab2bc471c7
    0x0c9dbd5d80e68ba3
    0x017fffffffffffff
    0x1fffffffffffffff
*/
uint8_t key[] = {
        0x0f, 0x6b, 0x75, 0xab, 0x2b, 0xc4, 0x71, 0xc7,
        0x0c, 0x9d, 0xbd, 0x5d, 0x80, 0xe6, 0x8b, 0xa3,
        0x10, 0xF5, 0xB6, 0x18, 0xBD, 0xB6, 0xF2, 0x26,
        0x2F, 0xCC, 0x59, 0x7B, 0xB2, 0x30, 0xB3, 0xEF
    };

uint8_t nonce[] = {
        0x00, 0x00, 0x00, 0x09, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
uint8_t counter[8] = {0x1};

extern int minunit_fail;
int chacha20_run_selftests (struct chacha20_context *ctx)
{
    MU_RUN_TEST(u32t8le_test);
    MU_RUN_TEST(u8t32le_test);
    MU_RUN_TEST(rotl32_test);
    MU_RUN_TEST(chacha20_quarterround_test_1);
    MU_RUN_TEST(chacha20_quarterround_test_2);
    MU_RUN_TEST(chacha20_serialize_test);
    MU_RUN_TEST(chacha20_block_test);
    MU_RUN_TEST(chacha20_init_state_test);
    MU_RUN_TEST(chacha20_xor_test);
    MU_REPORT();

   return minunit_fail;
}
