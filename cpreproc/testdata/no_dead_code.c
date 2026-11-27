#include <stdio.h>
#include <stdlib.h>

#ifdef USE_ALPHA
void maybe_alpha() {
    step_alpha();
}
#endif

#if 0x1
// This IS compiled — 0x1 is hex 1, not zero
void hex_one() {
    step_beta();
}
#endif

void always_live() {
    step_gamma();
}
