.PHONY: all
all: build attach run

.PHONY: build
build: redir score

.PHONY: redir
redir:
	clang -O2 -Wall -emit-llvm -g -c redir.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o redir.bpf.o

.PHONY: score
score:
	clang -O2 -lbpf score.c -o score.o
	sudo chmod +x score.o

.PHONY: attach
attach:
	sudo ./attach.sh $(IP)

.PHONY: run
run:
	sudo ./score.o

.PHONY: clean
clean:
	rm -rf *.log *.o

