.PHONY: all
all: build run

.PHONY: build
build: client

.PHONY: client
client:
	clang -O2 -lbpf client.c -o client.o
	sudo chmod +x client.o

.PHONY: run
run:
	./client.o $(FNAME)

.PHONY: clean
clean:
	rm -rf *.log *.o

