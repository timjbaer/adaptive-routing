CC=gcc
CFLAGS=-I.

psonar: perfsonar_metrics_standalone.c
	$(CC) -o psonar perfsonar_metrics_standalone.c

clean:
	rm -f psonar log.csv perfsonar_out.csv
