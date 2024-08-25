.PHONY: all
all: build attach run

.PHONY: build
build: ts seed

.PHONY: ts
ts:
	clang -O2 -Wall -emit-llvm -g -c ts.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o ts.bpf.o

.PHONY: seed
seed:
	clang -O2 -lbpf seed.c -o seed.o
	sudo chmod +x seed.o

.PHONY: attach
attach:
	sudo ./attach.sh $(IP)

.PHONY: run
run:
	sudo ./seed.o

.PHONY: clean
clean:
	rm -rf *.log *.o

