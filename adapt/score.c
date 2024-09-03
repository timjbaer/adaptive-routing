#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>
#include <string.h>

#include <ifaddrs.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/in.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "perfsonar_metrics.h"

#define PERFSONARCMDSIZE 100
#define PERFSONARINFOSIZE 100
#define PERFSONARDATASIZE 1024
#define FILENAMELENGTH 20
#define PINGPSKTS 5

static const char MAP_PATH[] = "/sys/fs/bpf/tc/globals/scores";
static const char BEST_TUNNEL_MAP_PATH[] = "/sys/fs/bpf/tc/globals/best_tunnel_map";

#define PING_CMD "ping -c 5 " // Ping command to send 5 ICMP packet

jmp_buf jump_destination;

void sigint_handler(int sg)
{
	longjmp(jump_destination, 1);
}

// Function to extract latency from ping output
double get_latency(const char *ip_address) {
    char cmd[100];
    snprintf(cmd, sizeof(cmd), "%s%s", PING_CMD, ip_address);

    FILE *fp;
    char output[1024];
    double latency[PINGPSKTS] = {0}; 
	double mean_latency=0.0;
	double sum=0.0;

    // Run the ping command and open the output stream
    fp = popen(cmd, "r");
    if (fp == NULL) {
        perror("popen failed");
        return mean_latency;
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
            //break; 
        }
		sum = sum + latency[ctr];
		ctr = ctr + 1;
    }
    pclose(fp);

	//Mean Latency
	mean_latency = sum / PINGPSKTS;

    return mean_latency;
}

int stats_update_per_IP(int map_fd, __u32 map_type, latency_stats *stats_rec, int tun_no, char* IP){

    char perfsonar_cmd[PERFSONARCMDSIZE] = {0};
    char analysis_cmd[100] = {0};
    char f_name[FILENAMELENGTH] = {0};
    char log_name[FILENAMELENGTH] = {0};

	__u32 key;
	__u64 value;
	double val;

	val= get_latency(IP);
	strcpy(stats_rec->interface, IP);
	stats_rec->mean_latency=float_to_fixed(val);

	printf("\n1. [STORE IN STATS MAP] To Host = %s (Tunnel # = %d) --> Mean Latency = %llu", stats_rec->interface, tun_no, stats_rec->mean_latency);

	value = stats_rec->mean_latency;

	//Writing to the map
	if (bpf_map_update_elem(map_fd, &tun_no, &value, BPF_ANY)){
		perror("bpf_map_update_elem");
	}

	//Reading back from the map for debugging
	// if (bpf_map_lookup_elem(map_fd, &tun_no, &value)){
	// 	perror("bpf_map_lookup_elem");
	// }else{
	// 	printf("\n2. [READ FROM STATS MAP] Key = %d,  Mean Latency = %llu", tun_no, value);
	// }

	return 0;
}

//finding minimum latency using perfsonar scores
__u32 find_min_latency(int map_fd){

	int err;
	
	__u64 min_value = __UINT64_MAX__;
	__u32 min_tunnel = 0;

	__u32 key, next_key;
	//perfSonar *value;
	__u64 value;

	//Start with the first key
	err = bpf_map_get_next_key(map_fd, NULL, &key);
	if (err < 0){
		perror("bpf_map_get_next_key");
		return min_tunnel;
	}
	do{
		// Lookup the value for the current key
		if (bpf_map_lookup_elem(map_fd, &key, &value) == 0){
			//printf("\n Current Entry Key: %d Value: %llu", key, value);
			//finding minimum
			if (value < min_value){
				min_value = value;
				min_tunnel = key;
			}
		} else {
			perror("bpf_map_lookup_elem");
		}

		//Get the next key
		err = bpf_map_get_next_key(map_fd, &key, &next_key);
		if (err == 0){
			key = next_key;
		}
	} while(err == 0);

	printf("\n[POST ANALYSIS : BEST LATENCY FROM STATS MAP] Key = %d Value = %llu\n", min_tunnel, min_value);

	return min_tunnel;
}

__u64 float_to_fixed(float value){
	return (unsigned long long) (value * FIXED_POINT_SCALE);
}

static void stats_poll(int map_fd, __u32 map_type, int num_tunnels, char **IPs){

        latency_stats record = {0};
        int update_ret;
		int best_tunnel_map_fd;

		__u32 key;
		__u32 best_tun_no;
		__u32 best_key = 42;

		printf("Number of IPs = %d\n", num_tunnels);

		printf("IPs are: ");
		for (int i = 1; i <= num_tunnels; i++)
			printf("%s ", IPs[i-1]);

		printf("\n");

		//Initial Updation of perfsonar_scores eBPF maps
		
		for (int tun_no = 1; tun_no <= num_tunnels; tun_no++){
			printf("\n------------------------------");
			printf("\nAnalyzing IP [%d/%d] = %s", tun_no, num_tunnels, IPs[tun_no-1]);
			printf("\n------------------------------");
			key = get_interface_index_from_ip(IPs[tun_no-1]);
			update_ret = stats_update_per_IP(map_fd, map_type, &record, key, IPs[tun_no-1]);
			if(update_ret == 1){
				printf("\n***********************\n");
				printf("\tERROR UPDATING MAP\t");
				printf("\n***********************\n\n\n");
			}
		}
        usleep(100); // 100 useconds sleep

		// Find best tunnel i.e., tunnel with least delay
		best_tun_no = find_min_latency(map_fd);

		//store that tunnel into best_tunnel_map
		best_tunnel_map_fd = bpf_obj_get(BEST_TUNNEL_MAP_PATH);

		if (bpf_map_update_elem(best_tunnel_map_fd, &best_key, &best_tun_no, BPF_ANY)){
			perror("bpf_map_update_elem");
		}

		//Reading from the Best Tunnel Map for Debugging
		//int value;
		// if (bpf_map_lookup_elem(best_tunnel_map_fd, &best_key, &value)) {
		// 	perror("bpf_map_lookup_elem");
		// }
		// printf("\n[READING FROM BEST TUNNEL MAP] Best Tunnel Index = %d\n", value);

        unsigned int count = 0;
		
		while(count < 3){
				for (int tun_no = 1; tun_no <= num_tunnels; tun_no++){
					 printf("\n------------------------------");
					printf("\nAnalyzing IP [%d/%d] = %s", tun_no, num_tunnels, IPs[tun_no-1]);
					printf("\n------------------------------");
					key = get_interface_index_from_ip(IPs[tun_no-1]);
                	update_ret = stats_update_per_IP(map_fd, map_type, &record, key, IPs[tun_no-1]);
					if(update_ret == 1){
						printf("\n***********************\n");
						printf("\tERROR UPDATING MAP\t");
						printf("\n***********************\n\n\n");
					}
					//perfsonar_stats_print(&record);
				}
                count = count + 1;
				// Find best tunnel i.e., tunnel with least delay
				best_tun_no = find_min_latency(map_fd);
				best_tunnel_map_fd = bpf_obj_get(BEST_TUNNEL_MAP_PATH);
				
				if (bpf_map_update_elem(best_tunnel_map_fd, &best_key, &best_tun_no, BPF_ANY)){
					perror("bpf_map_update_elem");
				}
				//Reading from the Best Tunnel Map for Debugging
				//printf("\n[READING FROM BEST TUNNEL MAP] Best Tunnel Index = %d\n", best_tun_no);
				sleep(POLLING_INTERVAL);
        }

		close(best_tunnel_map_fd);
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
                            (family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6),
                            host, NI_MAXHOST,
                            NULL, 0, NI_NUMERICHOST);

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



int main(int argc, char **argv)
{
	printf("running interface scoring\n");
	int fd, ret;

	int num_tunnels;
	char **IPs;

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

	num_tunnels = (argc-1);
	IPs = argv+1;

	stats_poll(fd, BPF_PROG_TYPE_SCHED_CLS, num_tunnels, IPs);
	close(fd);
	return 0;

cleanup:
	printf("cleaning up\n");
	close(fd);
	return 0;

}


/*{
	// Insert at key 0.
	__u32 k1 = 0;
	__u32 v1 = 25;
	ret = bpf_map_update_elem(fd, &k1, &v1, 0);
	if (ret < 0) {
		printf("error during bpf map update: %d\n", ret);
		goto cleanup;
	}

	// Lookup at key 0.
	__u32 k2 = 0;
	__u32 v2;
	ret = bpf_map_lookup_elem(fd, &k2, &v2);
	if (ret < 0) {
		printf("error during bpf map lookup: %d\n", ret);
		goto cleanup;
	}
	printf("key: %u, score: %u\n", k2, v2);

	// Spin...
	while (1) { }

cleanup:
	printf("cleaning up\n");
	close(fd);
	return 0;
}*/

