// Copyright (c) 2026 Zetier
// SPDX-License-Identifier: Apache-2.0
/* The deliberately debuggable victim for examples/ex11_the_thrower.py (x86-64, local).
 * A "device monitor" left in production: a text protocol on stdin/stdout speaking FICTIONAL
 * device addresses. "W <hexaddr> <hexbytes>" pokes bytes into a scratch page (the monitor
 * subtracts DEV_BASE and bounds-checks); "X" calls a function pointer out of that page --
 * the classic debug-monitor hijack. The poke primitive IS the vuln; no corruption needed.
 * Hex is lowercase (Python's bytes.hex() speaks it). Compiled at runtime with -O0 -Wall. */
#include <stdio.h>
#include <string.h>

#define DEV_BASE 0x20000000UL /* the fictional device VA of scratch[0]: the protocol's address space */
#define MAGIC_OFF 0x000       /* debug-unlock magic: X refuses to jump without it */
#define FPTR_OFF 0x100        /* the function-pointer slot X consumes */
#define ARG_OFF 0x108         /* the argument slot: fp((unsigned)arg) */

static unsigned char scratch[0x400];

void win(unsigned doorbell) { printf("win: doorbell=0x%x\n", doorbell); }

static int unhex(int c) { return c >= 'a' ? c - 'a' + 10 : c - '0'; }

int main(void) {
    char line[1100], hex[1025];
    unsigned long addr;
    setvbuf(stdout, 0, _IONBF, 0);
    printf("devmon: win @ 0x%lx\n", (unsigned long)win); /* the leak: PIE moves win every run */
    while (fgets(line, sizeof line, stdin)) {
        if (sscanf(line, "W %lx %1024s", &addr, hex) == 2) { /* NOLINT(cert-err34-c,bugprone-unchecked-string-to-number-conversion): a toy monitor parses trustingly by design */
            size_t off = addr - DEV_BASE, n = strlen(hex) / 2;
            if (addr < DEV_BASE || off + n > sizeof scratch) {
                printf("err W 0x%lx out of range\n", addr);
                continue;
            }
            for (size_t i = 0; i < n; i++)
                scratch[off + i] = (unsigned char)(unhex(hex[2 * i]) << 4 | unhex(hex[2 * i + 1]));
            printf("ok W 0x%lx\n", addr);
        } else if (line[0] == 'X') {
            void (*fp)(unsigned);
            unsigned long arg;
            if (memcmp(scratch + MAGIC_OFF, "cento-11", 8) != 0) {
                printf("err X locked\n"); /* the unlock magic must land BEFORE the trigger */
                continue;
            }
            memcpy(&fp, scratch + FPTR_OFF, sizeof fp); /* NOLINT(bugprone-multi-level-implicit-pointer-conversion): the overwritable function pointer IS the vulnerability */
            memcpy(&arg, scratch + ARG_OFF, sizeof arg);
            fp((unsigned)arg);
        }
    }
    return 0;
}
