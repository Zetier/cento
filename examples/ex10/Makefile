# The ex10 firmware fixtures: fw_v10.bin / fw_v11.bin ARE the dumps -- the checked-in source
# of truth the example verifies declarations against. The .lst files are hand-annotated
# sidecar listings; `make disasm` is the tool-derived read to eyeball them against, mapped to
# the gadget's real address (CTX_RESTORE at 0x40001000). The catalog/profile JSONs are plain
# data with no build step.
OBJDUMP ?= objdump
APT := binutils-multiarch
PPC_DISASM := -D -b binary -m powerpc -EB --adjust-vma=0x40001000

disasm: ## disassemble both dumps at the gadget's firmware address
	@$(OBJDUMP) -i 2>/dev/null | grep -q powerpc || { echo "$(OBJDUMP) cannot speak PPC -- make deps (apt: binutils-multiarch), or set OBJDUMP=powerpc-linux-gnu-objdump"; exit 1; }
	$(OBJDUMP) $(PPC_DISASM) fw_v10.bin
	$(OBJDUMP) $(PPC_DISASM) fw_v11.bin

deps: ## apt-install everything the targets above need (PPC-capable objdump)
	sudo apt-get install -y $(APT)

.PHONY: disasm deps
