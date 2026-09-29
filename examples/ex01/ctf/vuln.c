// Copyright (c) 2026 Zetier
// SPDX-License-Identifier: Apache-2.0
// vuln.c -- "smashme" (pwn 200): the classic 128-byte overflow with a libc leak.
//
// Shape: print where libc's puts really lives this run (ASLR leak), then
// read(0, buf, 0x200) into a 128-byte buffer and return -- the smashed saved
// RIP fires on the way out of vuln().
//
// The leak uses dlsym(RTLD_DEFAULT, "puts") because in a -no-pie binary a
// bare &puts evaluates to the (fixed) PLT stub, not the ASLR'd libc address.
#define _GNU_SOURCE
#include <dlfcn.h>
#include <stdio.h>
#include <unistd.h>

void vuln(void) {
    char buf[128];
    read(0, buf, 0x200);
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    printf("puts @ %p\n", dlsym(RTLD_DEFAULT, "puts"));
    vuln();
    return 0;
}
