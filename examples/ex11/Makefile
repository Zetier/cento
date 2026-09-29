# The ex11 victim: the example compiles devmon.c into ./devmon at runtime (the built binary
# is gitignored); this is the workbench path for driving the monitor by hand. Same flags.
CC ?= cc
CFLAGS := -O0 -Wall
APT := build-essential

all: devmon

devmon: devmon.c
	@command -v $(CC) >/dev/null || { echo "no $(CC) found -- make deps (apt: build-essential), or set CC=gcc"; exit 1; }
	$(CC) $(CFLAGS) -o $@ $<

deps: ## apt-install everything the targets above need (cc; python3 assumed)
	sudo apt-get install -y $(APT)

clean:
	rm -f devmon

.PHONY: all deps clean
