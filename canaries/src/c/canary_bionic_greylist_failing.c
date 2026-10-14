/*
 * canary_bionic_greylist_failing.c - Native library dynamically referencing libgui.so.
 * Blocked on targetSdk >= 24 (non-public platform library).
 */

#include <stdint.h>

/* Symbol declared in private libgui.so */
extern void _ZN7android13GraphicBufferC1Ejjij(void);

__attribute__((visibility("default")))
int canary_bionic_failing_symbol(void) {
    return 2;
}
