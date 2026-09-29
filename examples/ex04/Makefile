# The ex04 victim, out-of-line: the example assembles the ELF into a tempdir at runtime;
# this is the workbench path. victim.py is the toolchain -- encoders, opcodes, ELF writer.
PY ?= python3
QEMU ?= qemu-ppc
OBJDUMP ?= objdump
APT := qemu-user binutils-multiarch

all: build/vuln

build/vuln: victim.py
	mkdir -p build
	$(PY) -c "import pathlib, victim; p = pathlib.Path('$@'); p.write_bytes(victim.assemble_victim()[0]); p.chmod(0o755)"

run: build/vuln ## sanity run under qemu (QEMU=qemu-ppc-static if that is what you have; add -g <port> for the gdb stub)
	@command -v $(QEMU) >/dev/null || { echo "no $(QEMU) found -- make deps (apt: qemu-user), or set QEMU=qemu-ppc-static"; exit 1; }
	echo hello | $(QEMU) build/vuln

# The hand-packed ELF has no section headers (victim.py writes ehdr+phdr+code only), so plain
# `objdump -d` shows nothing; disassemble raw at the load address instead. Code starts at
# BASE+CODE_OFF = 0x10000054 (victim.py); the tail past the 31 instructions is message data.
disasm: build/vuln ## objdump the victim's code words at their load address
	@$(OBJDUMP) -i 2>/dev/null | grep -q powerpc || { echo "$(OBJDUMP) cannot speak PPC -- make deps (apt: binutils-multiarch), or set OBJDUMP=powerpc-linux-gnu-objdump"; exit 1; }
	$(OBJDUMP) -D -b binary -m powerpc -EB --adjust-vma=0x10000000 --start-address=0x10000054 build/vuln

deps: ## apt-install everything the targets above need (qemu-ppc, PPC-capable objdump; python3 assumed)
	sudo apt-get install -y $(APT)

clean:
	rm -rf build

.PHONY: all run disasm deps clean
