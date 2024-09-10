include ../var.sh

.PHONY: all
all: build attach run

.PHONY: build
build: redir score seed

.PHONY: redir
redir:
	clang -O2 -Wall -emit-llvm -g -c redir.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o redir.bpf.o

.PHONY: score
score:
	clang -O2 -lbpf score.c -o score.o
	sudo chmod +x score.o

.PHONY: seed
seed:
	clang -O2 -lbpf seed.c -o seed.o
	sudo chmod +x seed.o

.PHONY: attach
attach:
	sudo ./attach.sh

.PHONY: run
run:
	sudo ./seed.o
	sudo ./score.o ${TUN1_SRC_IP} ${TUN1_DST_IP} ${TUN2_SRC_IP} ${TUN2_DST_IP}

.PHONY: clean
clean:
	rm -rf *.log *.o
	sudo rm -rf /sys/fs/bpf/tc/globals/*

