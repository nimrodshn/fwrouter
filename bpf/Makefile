ARCH ?= $(shell uname -m | sed -e 's/aarch64/arm64/' -e 's/x86_64/x86/')

bytecode.$(ARCH).o: bpf.c
	clang \
	-target bpf \
 	-I/usr/include/$(shell uname -m)-linux-gnu \
	-g -O2 -c $< -o $@