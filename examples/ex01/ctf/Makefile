# smashme: the classic layout on purpose -- no canary, no PIE, no NX games.
CFLAGS = -O0 -fno-stack-protector -no-pie -z noexecstack

all: vuln offset-check

vuln: vuln.c
	gcc $(CFLAGS) -o vuln vuln.c

# Empirical saved-RIP offset check: buf must sit at rbp-0x80 in vuln(),
# giving the canonical 128 (buf) + 8 (saved rbp) = 136 bytes to saved RIP.
offset-check: vuln
	@objdump -d vuln | awk '/<vuln>:/{f=1} f&&/lea .*-0x80\(%rbp\)/{print "offset-check: buf @ rbp-0x80 -> saved RIP at 136. OK"; found=1; exit} f&&/ret/{exit} END{if(!found){print "offset-check FAILED: buf is not at rbp-0x80"; exit 1}}'

clean:
	rm -f vuln

.PHONY: all clean offset-check
