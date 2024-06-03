#include <stdint.h>
#include <stdio.h>

static uint64_t LFSR_GAMMA =   0x0af944215c1040f7ULL; // initialize LFSR register by Prime numbers

unsigned int AKalashnikovaGaloisRightLFSR (void)
{
//    printf("LFSR_GAMMA hex = 0x%lx\n", LFSR_GAMMA);

    uint32_t res = (uint32_t)(LFSR_GAMMA>>32); // 0xFFFFFFFF00000000u

    for (int j=0; j<32; j++ )
    {
        // taps:  64, 4, 3, 1, 0 ; feedback polynomial: G(x) = x^64 + x^4 + x^3 + x^1 + 1
        uint64_t feedback_bit = LFSR_GAMMA & 1u;  // Get LSB (i.e., the output bit).
        // 40:
        LFSR_GAMMA = (LFSR_GAMMA >> 1) ^ (-feedback_bit & 0xD800000000000000u);
        // 41:
        /*
        LFSR_GAMMA >>= 1;                                        // Shift register.
        if (feedback_bit)                                        // If the output bit is 1,
              LFSR_GAMMA ^= 0xD800000000000000u; //    apply toggle mask.
              // 1101100000000000000000000000000000000000000000000000000000000000
        */
        // 42:
        //LFSR_GAMMA >>= 1;                                        // Shift register.
        //LFSR_GAMMA ^= (-feedback_bit) & 0xD800000000000000u;

    }

    return res;
}
