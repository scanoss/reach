#include <stdio.h>
#include <stdlib.h>

// Line 4: Live
void live1() { step_alpha(); }

#if (0)
// Line 8: Dead — parenthesized zero
void dead_parens() { step_beta(); }
#endif

// Line 12: Live
void live2() { step_gamma(); }

#if 0x0
// Line 16: Dead — hex zero
void dead_hex() { step_delta(); }
#endif

// Line 20: Live
void live3() { step_epsilon(); }

#if 00
// Line 24: Dead — octal zero
void dead_octal() { step_zeta(); }
#endif

// Line 28: Live
void live4() { step_alpha(); }

#if !1
// Line 32: Dead — logical NOT 1
void dead_not() { step_eta(); }
#endif

// Line 36: Live
void live5() { step_beta(); }

#if 0 && FEATURE_ENABLED
// Line 40: Dead — short circuit
void dead_short() { step_theta(); }
#endif

// Line 44: Live
void live6() { step_iota(); }
