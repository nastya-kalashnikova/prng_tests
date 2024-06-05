#include "../../AKalashnikovaChaCha20Core.c"

uint32_t chacha20_random_ (struct chacha20_context *ctx)
{
    uint32_t *res;
    uint8_t *keystream8 = (uint8_t*)ctx->keystream32;

    if (ctx->position == -1)
    {
        // At first run selftest with RFC 7539 test vectors
        if (chacha20_run_selftests(&cc20ctx) > 0)
        {
            printf("Selftest with RFC 7539 test vectors: FAIL. Exit.\n");
            exit(EXIT_FAILURE);
        }
        printf("Selftest with RFC 7539 test vectors: PASSED.\n");

        chacha20_init_context(ctx, key, nonce, 1);
        printf("Status initialization: OK.\n");
        chacha20_block_next(ctx);
        ctx->position = 64;
    }

    if (ctx->position >= 64)
    {
        chacha20_block_next(ctx);
        ctx->position = 0;
    }
    res = (uint32_t *) &keystream8[ctx->position]; // or ctx->keystream32[ ctx->position/4 ]
    ctx->position += 4;

    return *res;
}

uint32_t chacha20_random (void)
{
    return chacha20_random_ (&cc20ctx);
}
