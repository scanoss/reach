#include <stdio.h>
#include <stdlib.h>

// Line 4: Live code
void live() {
    step_alpha();
}

#if 0
// Line 10: Dead — outer #if 0
void dead_outer() {
    step_beta();

    #ifdef USE_EXTRA
    // Line 15: Still dead — nested inside #if 0
    step_delta();
    #endif

    #if 1
    // Line 20: Still dead — nested inside outer #if 0
    step_epsilon();
    #endif
}
#endif

// Line 26: Live code
void live_after() {
    step_gamma();
}
