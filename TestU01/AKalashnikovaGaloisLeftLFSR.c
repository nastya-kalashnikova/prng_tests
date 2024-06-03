#include <testu01/unif01.h>
#include <testu01/bbattery.h>
#include <stdio.h>

unsigned int AKalashnikovaGaloisLeftLFSR (void);

int main (void)
{
   unif01_Gen *gen = unif01_CreateExternGenBits ("AKalashnikovaGaloisLeftLFSR", AKalashnikovaGaloisLeftLFSR);

   //gen = unif01_CreateExternGenBitsL ("AKalashnikovaGaloisLeftLFSR", AKalashnikovaGaloisLeftLFSR);

   bbattery_%%BATT_NAME%% (gen);

   unif01_DeleteExternGenBits (gen);

   return 0;
}
