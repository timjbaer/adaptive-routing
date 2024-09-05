#include <setjmp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <ifaddrs.h>
#include <linux/types.h>
#include <net/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <sys/types.h>

#include "score.h"

#define PERFSONARCMDSIZE 100
#define PERFSONARINFOSIZE 100
#define PERFSONARDATASIZE 1024
#define FILENAMELENGTH 20
#define PINGPSKTS 5

struct latency_ns {
  __u32 min;
  __u32 max;
  __u32 avg;
};

static const char MAP_PATH[] = "/sys/fs/bpf/tc/globals/intf_latency";

#define PING_CMD "ping -c 5 " // Ping command to send 5 ICMP packet

jmp_buf jump_destination;

void sigint_handler(int sg) { longjmp(jump_destination, 1); }

// Comparison function for qsort
int compare(const void *a, const void *b) {
  double fa = *(const double *)a;
  double fb = *(const double *)b;
  return (fa > fb) - (fa < fb);
}

// Function to extract latency from ping output
void get_latency(const char *ip_address, double latency[PINGPSKTS]) {
  char cmd[100];
  snprintf(cmd, sizeof(cmd), "%s%s", PING_CMD, ip_address);

  FILE *fp;
  char output[1024];
  // double latency[PINGPSKTS] = {0};

  // Run the ping command and open the output stream
  fp = popen(cmd, "r");
  if (fp == NULL) {
    perror("popen failed");
    return;
  }

  unsigned int ctr = 0;
  // Read the output line by line
  while (fgets(output, sizeof(output), fp) != NULL) {
    // Find the line that contains "time=" and parse the latency
    if (strstr(output, "time=") != NULL) {
      char *time_str = strstr(output, "time=");
      if (time_str != NULL) {
        sscanf(time_str, "time=%lf", &latency[ctr]);
      }
      // break;
    }
    ctr = ctr + 1;
  }
  pclose(fp);
}

double get_mean_latency(double latency[]) {

  double sum_latency = 0.0;

  for (int i = 0; i < PINGPSKTS; i++) {
    if ((latency[i] != __DBL_MAX__)) {
      sum_latency += latency[i];
    }
  }
  return (sum_latency / PINGPSKTS);
}

double get_max_latency(double latency[]) {

  double max_latency = 0.0;

  for (int i = 0; i < PINGPSKTS; i++) {
    if ((latency[i] != __DBL_MAX__) && (latency[i] >= max_latency)) {
      max_latency = latency[i];
    }
  }
  return max_latency;
}

double get_median_latency(double latency[]) {
  // Sort the array
  qsort(latency, PINGPSKTS, sizeof(double), compare);

  // If the number of elements is odd, return the middle element
  if (PINGPSKTS % 2 != 0) {
    return latency[PINGPSKTS / 2];
  }
  // If the number of elements is even, return the average of the two middle
  // elements
  else {
    return (latency[(PINGPSKTS - 1) / 2] + latency[PINGPSKTS / 2]) / 2.0;
  }
}

__u64 float_to_fixed(float value) {
  return (unsigned long long)(value * FIXED_POINT_SCALE);
}

int stats_update_per_IP(int map_fd, latency_stats *stats_rec, int tun_no,
                        char *IP) {
  double latency_values[PINGPSKTS];
  get_latency(IP, latency_values);
  double mean_val = get_mean_latency(latency_values);
  double max_val = get_max_latency(latency_values);
  double median_val = get_median_latency(latency_values);

  strcpy(stats_rec->interface, IP);
  stats_rec->mean_latency = float_to_fixed(mean_val);
  stats_rec->median_latency = float_to_fixed(median_val);
  __u64 cur_max_latency = float_to_fixed(max_val);

  //Read previous max latency in the map
  __u64 prev_max_latency = 0.0;
  struct latency_ns prev_lat;
	if (bpf_map_lookup_elem(map_fd, &tun_no, &prev_lat)){
		perror("bpf_map_lookup_elem");
	}else{
		prev_max_latency = prev_lat.max;
    printf("\n2. [READ FROM STATS MAP] Key = %d,  Prev. Max Latency = %llu, Current Max. Latency = %llu", tun_no, prev_max_latency, cur_max_latency);
	}

  //Update the max latency only if the new value is higher
  if (cur_max_latency >= prev_max_latency)
    stats_rec->max_latency = cur_max_latency;
  else
    stats_rec->max_latency = prev_max_latency;

  printf("\n1. [STORE IN STATS MAP] To Host = %s (Tunnel # = %d) --> Mean "
         "Latency = %llu Max Latency = %llu Median Latency = %llu",
         stats_rec->interface, tun_no, stats_rec->mean_latency,
         stats_rec->max_latency, stats_rec->median_latency);
  struct latency_ns lat = {stats_rec->min_latency, stats_rec->max_latency,
                           stats_rec->median_latency};

  if (bpf_map_update_elem(map_fd, &tun_no, &lat, 0) < 0) {
    perror("bpf_map_update_elem");
  }

  return 0;
}

__u32 get_interface_index_from_ip(const char *ip_address) {
  struct ifaddrs *ifaddr, *ifa;
  int family, s;
  __u32 interface_index = 0;
  char host[NI_MAXHOST];

  // Get the list of network interfaces
  if (getifaddrs(&ifaddr) == -1) {
    perror("getifaddrs");
    return -1;
  }

  // Loop through the list of network interfaces
  for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == NULL)
      continue;

    family = ifa->ifa_addr->sa_family;

    // Check for IPv4 or IPv6 family
    if (family == AF_INET || family == AF_INET6) {
      // Convert the address to a readable form
      s = getnameinfo(ifa->ifa_addr,
                      (family == AF_INET) ? sizeof(struct sockaddr_in)
                                          : sizeof(struct sockaddr_in6),
                      host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);

      if (s != 0) {
        fprintf(stderr, "getnameinfo() failed: %s\n", gai_strerror(s));
        continue;
      }

      // Compare the provided IP address with the current interface address
      if (strcmp(host, ip_address) == 0) {
        // Get the interface index
        interface_index = if_nametoindex(ifa->ifa_name);
        break;
      }
    }
  }

  // Free the interface list
  freeifaddrs(ifaddr);

  return interface_index;
}

static void stats_poll(int map_fd, int num_tunnels, char **IPs) {
  int ret;
  latency_stats record = {0};

  printf("Number of IPs = %d\n", num_tunnels);

  printf("IPs are: ");
  for (int i = 1; i <= num_tunnels; i++)
    printf("%s ", IPs[i - 1]);

  printf("\n");

  for (int count = 0; count < 3; ++count) {
    for (int tun_no = 0; tun_no < num_tunnels; tun_no++) {
      printf("\n------------------------------");
      printf("\nAnalyzing IP [%d/%d] = %s --> %s", tun_no, num_tunnels,
             IPs[2 * tun_no], IPs[2 * tun_no + 1]);
      printf("\n------------------------------");
      int key = get_interface_index_from_ip(IPs[2 * tun_no]);
      ret = stats_update_per_IP(map_fd, &record, key, IPs[2 * tun_no + 1]);
      if (ret == 1) {
        printf("\n***********************\n");
        printf("\tERROR UPDATING MAP\t");
        printf("\n***********************\n\n\n");
      }
      // perfsonar_stats_print(&record);
    }
    sleep(POLLING_INTERVAL);
  }
}

int main(int argc, char **argv) {
  printf("running interface scoring\n");
  int fd, ret;

  int num_tunnels = (argc - 1) / 2;
  char **IPs = argv + 1;

  // Handle SIGINT and errors.
  if (setjmp(jump_destination) == 1) {
    goto cleanup;
  }

  // Get pinned interface scores BPF map.
  fd = bpf_obj_get(MAP_PATH);
  if (fd < 0) {
    printf("error during bpf open file: %d\n", ret);
    goto cleanup;
  }

  stats_poll(fd, num_tunnels, IPs);

cleanup:
  printf("cleaning up\n");
  close(fd);
  return 0;
}
