#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <signal.h>
#include <setjmp.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/types.h>
#include "perfsonar_metrics.h"

#define PERFSONARCMDSIZE 100
#define PERFSONARINFOSIZE 100
#define PERFSONARDATASIZE 1024
#define FILENAMELENGTH 20

static const char MAP_PATH[] = "/sys/fs/bpf/tc/globals/perfsonar_scores";
static const char BEST_TUNNEL_MAP_PATH[] = "/sys/fs/bpf/tc/globals/best_tunnel_map";

jmp_buf jump_destination;

void sigint_handler(int sg)
{
	longjmp(jump_destination, 1);
}

static void perfsonar_stats_print(perfSonar *stats_rec){

        perfSonar *val;
        double period;

        __u64 packets;

        val = stats_rec;

        printf("perfSonar Stats: \n\n");
        for (unsigned int tun_no=1; tun_no <= NUM_TUNNELS; tun_no++){
                printf("Median Latency in String %llu\n", val->median_latency);
				printf("Min Latency in String %llu\n", val->min_latency);
				printf("Max Latency in String %llu\n", val->max_latency);
				printf("Mean Latency in String %llu\n", val->mean_latency);

        }
}

int perfsonar_stats_update_per_IP(int map_fd, __u32 map_type, perfSonar *stats_rec, int tun_no, char* IP){

    char perfsonar_cmd[PERFSONARCMDSIZE] = {0};
    char analysis_cmd[100] = {0};
    char f_name[FILENAMELENGTH] = {0};
    char log_name[FILENAMELENGTH] = {0};

	__u32 key;
	__u64 value;

	printf("\n***********************\n");
	printf("Start %s", __func__);
	printf("\n***********************\n\n\n");

    strcpy(f_name, "perfsonar_out.csv");
    FILE* perfsonar_file = fopen(f_name, "w+");

    if (perfsonar_file == NULL) {
        printf("Could not open file\n");
        return 1;
    }

	strcpy(log_name, "log.csv");
    FILE* file = fopen(log_name, "w+");

    if (file == NULL) {
        printf("Could not open file\n");
        return 1;
    }

    sprintf(perfsonar_cmd, "pscheduler task latency --dest %s > %s", IP, f_name);
    printf("Executing perfsonar command %s\n", perfsonar_cmd);
    system(perfsonar_cmd);

    sprintf(analysis_cmd, "cat %s | grep -A 8 'Delay Median' > %s", f_name, log_name);
    printf("Executing analysis command : %s\n", analysis_cmd);
    system(analysis_cmd);

    char line[PERFSONARDATASIZE];
    unsigned int line_ct = 0;
    unsigned int pos = 0;
    char *token;
    while (fgets(line, PERFSONARDATASIZE, file)) {
        char* tmp = strdup(line);
        //printf("\n\n Considering : %s ", tmp);
        line_ct++;
        pos = 0;	
		switch(line_ct){
				case 1: for (char *p = strtok(tmp, " "); p != NULL; p = strtok(NULL, " ")){
						//printf("Token = %s\n", p);
								if(pos == 3){
										token = strdup(p);
										printf("Median Latency in String %s\n", token);
										stats_rec->median_latency = float_to_fixed(atof(token));
								}
								pos++;
						}
						break;

				case 2: for (char *p = strtok(tmp, " "); p != NULL; p = strtok(NULL, " ")){
						//printf("Token = %s\n", p);
								if (pos == 3){
										token = strdup(p);
										printf("Min Latency in String %s\n", token);
										stats_rec->min_latency = float_to_fixed(atof(token));
								}
								pos++;
						}
						break;

				case 3: for (char *p = strtok(tmp, " "); p != NULL; p = strtok(NULL, " ")){
						//printf("Token = %s\n", p);
								if (pos == 3){
										token = strdup(p);
										printf("Max Latency in String %s\n", token);
										stats_rec->max_latency = float_to_fixed(atof(token));
								}
								pos++;
						}
						break;

				case 4: for (char *p = strtok(tmp, " "); p != NULL; p = strtok(NULL, " ")){
						//printf("Token = %s\n", p);
								if (pos == 3){
										token = strdup(p);
										printf("Mean Latency in String %s\n", token);
										stats_rec->mean_latency = float_to_fixed(atof(token));
								}
								pos++;
						}
						break;

		}
		free(tmp);
		line_ct += 1;
    }

	fclose(file);
	printf("To Host = %s (Tunnel # = %d) --> Median Latency = %llu\tMin. Latency = %llu\tMax. Latency = %llu\tMean Latency = %llu\n", IP, tun_no, stats_rec->median_latency, stats_rec->min_latency, stats_rec->max_latency, stats_rec->mean_latency);

	//key = tun_no;
	//value = stats_rec;
	value = stats_rec->median_latency;

	if (bpf_map_update_elem(map_fd, &tun_no, &value, BPF_ANY)){
		perror("bpf_map_update_elem");
	}

	if (bpf_map_lookup_elem(map_fd, &tun_no, &value)){
		perror("bpf_map_lookup_elem");
	}else{
		printf("%d: Median Latency = %llu", __LINE__, value);
	}


	printf("\n***********************\n");
	printf("End %s", __func__);
	printf("\n***********************\n\n\n");
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

	printf("\n***********************\n");
	printf("Start %s", __func__);
	printf("\n***********************\n\n\n");

	//Start with the first key
	err = bpf_map_get_next_key(map_fd, NULL, &key);
	if (err < 0){
		perror("bpf_map_get_next_key");
		return min_tunnel;
	}

	printf("Ashish = %d", key);

	do{
		// Lookup the value for the current key
		if (bpf_map_lookup_elem(map_fd, &key, &value) == 0){
			printf("Key: %d Value: %llu", key, value);
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



	//Iterate over the perfsonar_scores map
	// while(bpf_map_get_next_key(map_fd, &prev_tun, &tun) == 0) {

	// 	err = bpf_map_lookup_elem(map_fd, &tun, value);
	// 	if (err == 0){
	// 		if (value->mean_latency < min_value){
	// 			min_value = value->median_latency;
	// 			min_tunnel = tun;
	// 		}
	// 	}
	// 	else{
	// 		perror("Failed to iterate over map");
	// 		return -1;
	// 	}

	// 	prev_tun = tun;
	// }

	printf("\n***********************\n");
	printf("End %s", __func__);
	printf("\n***********************\n\n\n");

	return min_tunnel;


}

__u64 float_to_fixed(float value){
	return (unsigned long long) (value * FIXED_POINT_SCALE);
}

static void perfsonar_stats_poll (int map_fd, __u32 map_type, int num_tunnels, char **IPs){

        perfSonar record = {0};
        int update_ret;
		int best_tunnel_map_fd;

		int value;

		printf("\n***********************\n");
		printf("Start %s", __func__);
		printf("\n***********************\n\n\n");
		printf("Number of IPs = %d\n", num_tunnels);

		printf("IPs are: ");
		for (int i = 1; i <= num_tunnels; i++)
			printf("%s ", IPs[i-1]);

		printf("\n");

		//Initial Updation of perfsonar_scores eBPF maps 
		for (int tun_no = 1; tun_no <= num_tunnels; tun_no++){
			printf("Analyzing IP = %s\n\n", IPs[tun_no-1]);
			update_ret = perfsonar_stats_update_per_IP(map_fd, map_type, &record, tun_no, IPs[tun_no-1]);
			if(update_ret == 1){
				printf("\n***********************\n");
				printf("\tERROR UPDATING MAP\t");
				printf("\n***********************\n\n\n");
			}
		}
        usleep(100); // 100 useconds sleep

		// Find best tunnel i.e., tunnel with least delay
		__u32 tun_no = find_min_latency(map_fd);

		printf("%d: Best tunnel value = %d\n", __LINE__, tun_no);

		//store that tunnel into best_tunnel_map
		best_tunnel_map_fd = bpf_obj_get(BEST_TUNNEL_MAP_PATH);
		printf("Best Tunnel Map File Descriptor = %d\n", best_tunnel_map_fd);
		__u32 key = 42;

		if (bpf_map_update_elem(best_tunnel_map_fd, &key, &tun_no, BPF_ANY)){
			perror("bpf_map_update_elem");
		}

		//print the best tunnel for debigging
		if (bpf_map_lookup_elem(best_tunnel_map_fd, &key, &value)) {
			perror("bpf_map_lookup_elem");
		}

		printf("%d: Best tunnel value = %d\n", __LINE__, value);

		printf("\n***********************\n");
		printf("End %s", __func__);
		printf("\n***********************\n\n\n");

        while(1){
                printf("------------------------------\n\n\n");
				for (int tun_no = 1; tun_no <= num_tunnels; tun_no++){
					printf("Analyzing IP = %s\n\n", IPs[tun_no-1]);
                	update_ret = perfsonar_stats_update_per_IP(map_fd, map_type, &record, tun_no, IPs[tun_no-1]);
					if(update_ret == 1){
						printf("\n***********************\n");
						printf("\tERROR UPDATING MAP\t");
						printf("\n***********************\n\n\n");
					}
					//perfsonar_stats_print(&record);
				}
                sleep(POLLING_INTERVAL);
        }

		close(best_tunnel_map_fd);
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

	// printf("Number of IPs = %d\n", num_tunnels);

	// printf("IPs are: ");
	// for (int i = 1; i <= num_tunnels; i++)
	// 	printf("%s ", IPs[i-1]);

	// printf("\n");

	printf("Perfsonar File Descriptor = %d\n", fd);
	perfsonar_stats_poll(fd, BPF_PROG_TYPE_SCHED_CLS, num_tunnels, IPs);
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

