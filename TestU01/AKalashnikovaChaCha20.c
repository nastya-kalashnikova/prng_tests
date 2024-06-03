#include <testu01/unif01.h>
#include <testu01/bbattery.h>
#include <stdio.h>

uint32_t chacha20_random (void);

int main (void)
{
   unif01_Gen *gen = unif01_CreateExternGenBits ("AKalashnikova ChaCha20", chacha20_random);

   bbattery_%%BATT_NAME%% (gen);

   unif01_DeleteExternGenBits (gen);

   return 0;
}
