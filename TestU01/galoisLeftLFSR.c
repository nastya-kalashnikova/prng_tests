#include <stdint.h>
#include <stdio.h>

static uint64_t LFSR_GAMMA = 0x0af944215c1040f7ULL; // initialize LFSR register by Prime numbers

unsigned int AKalashnikovaGaloisLeftLFSR (void)
{
//    printf("LFSR_GAMMA hex = 0x%lx\n", LFSR_GAMMA);

    uint32_t *pUi = (uint32_t *)&LFSR_GAMMA; // LFSR_GAMMA & 0x00000000FFFFFFFFu
    *pUi ^= 1;
    unsigned int res = *pUi;
    //uint32_t res = (uint32_t)LFSR_GAMMA; // LFSR_GAMMA & 0x00000000FFFFFFFFu

    for (int j=0; j<32; j++ )
    //for (int j=0; j<8; j++ )
    {
        // taps:  64, 4, 3, 1, 0 ; feedback polynomial: G(x) = x^64 + x^4 + x^3 + x^1 + 1
        uint64_t feedback_bit = (int64_t)LFSR_GAMMA < 0;          // Get MSB (i.e., the output bit).
        LFSR_GAMMA <<= 1;                                         // Shift register.
        if (feedback_bit)                                         // If the output bit is 1,
            LFSR_GAMMA ^= 0x000000000000001Bu;                    //     apply toggle mask.
            // 0000000000000000000000000000000000000000000000000000000000011011
    }

    return res;
}
