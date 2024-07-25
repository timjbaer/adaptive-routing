all: build run

build: redir attach score

redir:
	clang -O2 -Wall -emit-llvm -g -c redir.bpf.c -o - | \
	llc -march=bpf -mcpu=probe -filetype=obj -o redir.bpf.o

attach:
	sudo ./configure.sh 30.0.0.0/16
	# TODO: remove pinning
	-sudo rm /sys/fs/bpf/tb/intf_scores
	sudo bpftool map pin name intf_scores /sys/fs/bpf/tb/intf_scores

score:
	clang -O2 -lbpf score.c -o score.o
	sudo chmod +x score.o

run:
	sudo ./score.o

clean:
	rm -rf *.log redir.bpf.o score.o

