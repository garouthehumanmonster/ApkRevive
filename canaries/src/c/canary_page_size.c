/*
 * canary_page_size.c - Canary native library for 64-bit ELF page size alignment testing.
 * Targets arm64-v8a architectures with 16KB and 4KB p_align segments.
 */

#include <stdint.h>

__attribute__((visibility("default")))
uint64_t canary_page_size_probe(void) {
    return 16384ULL;
}
