all: build attach run

build: redir score

redir:
	clang -O2 -Wall -emit-llvm -g -c redir.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o redir.bpf.o

score:
	clang -O2 -lbpf score.c -o score.o
	sudo chmod +x score.o

attach:
	sudo ./attach.sh $(CIDR)

run:
	sudo ./score.o

clean:
	rm -rf *.log *.o

