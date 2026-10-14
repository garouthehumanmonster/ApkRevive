/*
 * canary_bionic_greylist_control.c - Native library dynamically referencing libcrypto.so.
 * Permitted under Bionic linker greylist when targetSdk < 24.
 */

#include <stdint.h>

/* Symbol declared in libcrypto.so */
extern void CRYPTO_malloc(void);

__attribute__((visibility("default")))
int canary_bionic_control_symbol(void) {
    return 1;
}
