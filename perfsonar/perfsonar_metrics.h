#ifndef __PERFSONAR_METRICS_H
#define __PERFSONAR_METRICS_H

#define NUM_TUNNELS 4
#define NUM_METRICS 10
#define IF_NAMESIZE 32
#define EXIT_OK 0
#define EXIT_FAIL 1

/* Representation of perfSonar metrics */
typedef struct {
    char interface[IF_NAMESIZE];
    float median_latency;
    float min_latency;
    float max_latency;
    float mean_latency;
}perfSonar;

/* Representation of a tunnel interface */

typedef struct {
    char ifname[IF_NAMESIZE]; // name of the tunnel interface
}tunnel;

int run_experiment_per_ip(char* IP, int tun_no, perfSonar* PS);

#endif /* __PERFSONAR_METRICS_H */
