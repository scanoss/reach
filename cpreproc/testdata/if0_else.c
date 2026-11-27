#include <stdio.h>
#include <stdlib.h>

#if 0
// Line 5: Dead code — the #if 0 branch
void dead_branch() {
    step_alpha();
}
#else
// Line 10: LIVE code — the #else branch IS compiled
void live_branch() {
    step_beta();
}
#endif

// Line 16: Live code
void normal() {
    step_gamma();
}
