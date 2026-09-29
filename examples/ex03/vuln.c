// Copyright (c) 2026 Zetier
// SPDX-License-Identifier: Apache-2.0
/* The deliberately vulnerable victim for examples/ex03_local_ret2win.py (x86-64, local).
 * Compiled at runtime with -O0 -fno-stack-protector -no-pie; see the example for the walkthrough. */
#define _GNU_SOURCE
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <ucontext.h>
#include <unistd.h>

/* win() prints via raw write(): a straight ret leaves rsp 8-misaligned, and stdio's SSE
 * spills would fault on it -- the classic ret2win gotcha. Syscall wrappers do not care. */
void win(void) {
    static const char msg[] = "win: control of rip\n";
    write(1, msg, sizeof msg - 1);
    _exit(0);
}

/* The debug fault handler every embedded device grows eventually: on a crash, print where we
 * were and the word at the stack pointer. ret to a non-canonical address faults ON the ret,
 * return address still at [rsp] -- exactly what an attacker wants logged. */
static void boom(int sig, siginfo_t *si, void *uctx) {
    (void)sig;
    (void)si;
    ucontext_t *uc = uctx;
    unsigned long long rip = uc->uc_mcontext.gregs[REG_RIP];
    unsigned long long rsp = uc->uc_mcontext.gregs[REG_RSP];
    dprintf(2, "segfault: rip=0x%llx stack0=0x%llx\n", rip, *(unsigned long long *)rsp);
    _exit(139);
}

void vuln(void) {
    char buf[64];
    read(0, buf, 0x100); /* the bug: 0x100 bytes into a 64-byte buffer */
}

int main(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_sigaction = boom;
    sa.sa_flags = SA_SIGINFO;
    sigaction(SIGSEGV, &sa, 0);
    vuln();
    dprintf(1, "returned normally\n");
    return 0;
}
