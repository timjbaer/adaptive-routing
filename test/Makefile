.PHONY: all
all: build run

.PHONY: build
build: overwrite_latency

.PHONY: overwrite_latency
overwrite_latency:
	clang -O2 -lbpf overwrite_latency.c -o overwrite_latency.o
	sudo chmod +x overwrite_latency.o

.PHONY: run
run:
	sudo ./overwrite_latency.o

.PHONY: clean
clean:
	rm -rf *.log *.o

