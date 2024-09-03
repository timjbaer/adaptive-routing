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
	# sudo ./attach.sh $(PUB_IP)
	sudo ./attach.sh 172.31.1.27

.PHONY: run
run:
	sudo ./seed.o
	# sudo ./score.o ${TUN_IPS[@]}
	sudo ./score.o 172.31.1.27 127.0.0.1

.PHONY: clean
clean:
	rm -rf *.log *.o

