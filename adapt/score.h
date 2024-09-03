#ifndef __SCORE_H
#define __SCORE_H

#define NUM_TUNNELS 4
#define NUM_METRICS 10
#define EXIT_OK 0
#define EXIT_FAIL 1
#define POLLING_INTERVAL 2
#define TUN_IF_NAMESIZE 16
#define FIXED_POINT_SCALE 1000000

typedef struct {
  char interface[TUN_IF_NAMESIZE];
  __u64 median_latency;
  __u64 min_latency;
  __u64 max_latency;
  __u64 mean_latency;
} latency_stats;

static void stats_poll(int map_fd, int num_tunnels, char **IPs);

__u32 get_interface_index_from_ip(const char *ip_address);

int stats_update_per_IP(int map_fd, latency_stats *stats_rec, int tun_no,
                        char *IP);

__u64 float_to_fixed(float value);

__u32 find_min_latency(int map_fd);

#endif /* __SCORE_H */
