#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "perfsonar_metrics.h"

int main(int argc, char** argv) {

    /*sprintf(cmd, "pscheduler task latency --dest 172.31.20.237 > %s", f_name);*/

    printf("Number of IPs = %d\n", (argc-1));

    perfSonar latency_metrics[10];
    
    for (int x = 1; x < argc; x++){
	    run_experiment_per_ip(argv[x], x, latency_metrics);
    }
    return 0;
}

int run_experiment_per_ip(char* IP, int tun_no, perfSonar* latency_metrics){
    
    char analysis_cmd[100] = {0};
    char perfsonar_cmd[100] = {0};
    char f_name[20] = {0};
    char log_name[20] = {0};
    
    strcpy(f_name, "perfsonar_out.csv");
    FILE* perfsonar_file = fopen(f_name, "w+");
    
    if (perfsonar_file == NULL){
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
    printf("Executing perfsonar Command : %s\n", perfsonar_cmd);
    system(perfsonar_cmd);

    sprintf(analysis_cmd, "cat %s | grep -A 8 'Delay Median' > %s", f_name, log_name);
    printf("Executing Analysis Command : %s\n", analysis_cmd);
    system(analysis_cmd);

    char line[1024];
    int line_ct = 0;
    int pos = 0;
    char *token;
    while (fgets(line, 1024, file)) {
        char* tmp = strdup(line);
        //printf("\n\n Considering : %s ", tmp);
	line_ct++;
	pos = 0;
	switch(line_ct){
		case 1: for (char *p = strtok(tmp, " "); p != NULL; p = strtok(NULL, " ")){
				//printf("Token = %s\n", p);
				if (pos == 3){
					token = strdup(p);
					printf("Median Latency in String %s\n", token);
					latency_metrics[tun_no].median_latency = atof(token);
				}
				pos++;
			}
			break;

		case 2: for (char *p = strtok(tmp," "); p != NULL; p = strtok(NULL, " ")){
				//printf("Token = %s\n", p);
				if (pos == 3){
					token = strdup(p);
					printf("Min Latency in String %s\n", token);
					latency_metrics[tun_no].min_latency = atof(token);
				}
				pos++;
			}
			break;

		case 3: for (char *p = strtok(tmp," "); p != NULL; p = strtok(NULL, " ")){
				//printf("Token = %s\n", p);
				if (pos == 3){
					token = strdup(p);
					printf("Max Latency in String %s\n", token);
					latency_metrics[tun_no].max_latency = atof(token);
				}
				pos++;
			}
			break;

		case 4: for (char *p = strtok(tmp," "); p != NULL; p = strtok(NULL, " ")){
				//printf("Token = %s\n", p);
				if (pos == 3){
					token = strdup(p);
					printf("Mean Latency in String %s\n", token);
					latency_metrics[tun_no].mean_latency = atof(token);
				}
				pos++;
			}
			break;

	}
        free(tmp);
    }

    fclose(file);

    printf("To Host = %s --> Median Latency = %f\tMin. Latency = %f\tMax. Latency = %f\tMean Latency = %f\n", IP, latency_metrics[tun_no].median_latency, latency_metrics[tun_no].min_latency, latency_metrics[tun_no].max_latency, latency_metrics[tun_no].mean_latency);
    return 0;
}
