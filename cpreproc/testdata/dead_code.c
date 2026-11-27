#include <stdio.h>
#include <stdlib.h>

// Line 4: Live code — compiled
void live_function() {
    step_alpha();
}

#if 0
// Line 10: Dead code — disabled by #if 0
void dead_function() {
    step_beta();
}
#endif

// Line 16: Live code — compiled
void another_live() {
    step_gamma();
}

#if 0
// Line 22: Dead code block 2
void also_dead() {
    step_delta();
}
#endif
