# The ex03 victim, out-of-line: the example compiles vuln.c into a tempdir at runtime;
# this is the workbench path for poking at the binary directly. Same flags as the example.
CC ?= cc
PY ?= python3
CFLAGS := -O0 -fno-stack-protector -no-pie
APT := build-essential

all: build/vuln

build/vuln: vuln.c
	@command -v $(CC) >/dev/null || { echo "no $(CC) found -- make deps (apt: build-essential), or set CC=gcc"; exit 1; }
	mkdir -p build
	$(CC) $(CFLAGS) -o $@ $<

crash: build/vuln ## step 1 of the example by hand: throw the self-locating pad, read the fault handler's report
	PYTHONPATH=../../src $(PY) -c "import sys, cento; sys.stdout.buffer.write(cento.region('frame', max_size=0x84, pad=4, endian='little').image())" | ./build/vuln || true

disasm: build/vuln ## win/vuln disassembly: see the misaligned-rsp and fault-handler notes in vuln.c
	objdump -d --no-show-raw-insn build/vuln | awk '/<(win|vuln|boom)>:/{f=1} f{print} f&&/ret/{f=0; print ""}'

deps: ## apt-install everything the targets above need (cc, objdump; python3 assumed)
	sudo apt-get install -y $(APT)

clean:
	rm -rf build

.PHONY: all crash disasm deps clean
