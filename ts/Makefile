.PHONY: all
all: build attach

.PHONY: build
build: ts

.PHONY: ts
ts:
	clang -O2 -Wall -emit-llvm -g -c ts.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o ts.bpf.o

.PHONY: attach
attach:
	sudo ./attach.sh $(IP)

.PHONY: clean
clean:
	rm -rf *.log *.o

