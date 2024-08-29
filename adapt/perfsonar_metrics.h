#ifndef __PERFSONAR_METRICS_H
#define __PERFSONAR_METRICS_H

#define NUM_TUNNELS 4
#define NUM_METRICS 10
#define IF_NAMESIZE 32
#define EXIT_OK 0
#define EXIT_FAIL 1
#define POLLING_INTERVAL 2

/* Representation of perfSonar metrics */
typedef struct {
    char interface[IF_NAMESIZE];
    __u64 median_latency;
    __u64 min_latency;
    __u64 max_latency;
    __u64 mean_latency;
}perfSonar;

// typedef struct {
//         __u64 timestamp;
//         perfSonar record;
// }perfSonarRecord;

/* Representation of a tunnel interface */
typedef struct {
    char ifname[IF_NAMESIZE]; // name of the tunnel interface
}tunnel;

int run_experiment_per_ip(char* IP, int tun_no, perfSonar* PS);

#endif /* __PERFSONAR_METRICS_H */