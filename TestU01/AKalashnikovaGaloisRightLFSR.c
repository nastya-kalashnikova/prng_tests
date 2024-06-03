#include <testu01/unif01.h>
#include <testu01/bbattery.h>
#include <stdio.h>

unsigned int AKalashnikovaGaloisRightLFSR (void);

int main (void)
{
   unif01_Gen *gen = unif01_CreateExternGenBits ("AKalashnikovaGaloisRightFSR", AKalashnikovaGaloisRightLFSR);

   bbattery_%%BATT_NAME%% (gen);

   unif01_DeleteExternGenBits (gen);

   return 0;
}
