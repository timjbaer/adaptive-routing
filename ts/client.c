#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define DEBUG 1
#define MTU_SIZE 1500
#define IP_HDR_SIZE 20
#define TCP_HDR_SIZE 20
#define CSTM_HDR_SIZE (2 * sizeof(uint64_t))
#define BUFFER_SIZE (MTU_SIZE - IP_HDR_SIZE - TCP_HDR_SIZE - CSTM_HDR_SIZE)
#define AF21 18

ssize_t send_with_timestamp(int sockfd, const void *data, size_t len,
                            int64_t wall_ns, int64_t dead_ns) {
  char buffer[BUFFER_SIZE + CSTM_HDR_SIZE];
  char header[CSTM_HDR_SIZE];

  memcpy(buffer, &wall_ns, sizeof(uint64_t));
  memcpy(buffer + sizeof(uint64_t), &dead_ns, sizeof(uint64_t));

  memcpy(buffer + CSTM_HDR_SIZE, data, len);

  return send(sockfd, buffer, CSTM_HDR_SIZE + len, 0);
}

int main(int argc, char *argv[]) {
  int ret = 0;
  int sock, fd;
  struct sockaddr_in server_addr;

  if (argc != 5) {
    fprintf(
        stderr,
        "Usage: %s <server_ip> <server_port> <file_to_send> <deadline_ns>\n",
        argv[0]);
    return -1;
  }

  char *server_ip = argv[1];
  int server_port = atoi(argv[2]);
  char *fname = argv[3];
  long latency_ns = strtol(argv[4], NULL, 10);

  if ((ret = sock = socket(AF_INET, SOCK_STREAM, 0)) < 0)
    goto cleanup;

  int dscp = AF21 << 2;
  if ((ret = setsockopt(sock, IPPROTO_IP, IP_TOS, &dscp, sizeof(dscp))) < 0)
    goto cleanup;

  memset(&server_addr, 0, sizeof(server_addr));
  server_addr.sin_family = AF_INET;
  server_addr.sin_port = htons(server_port);

  if ((ret = inet_pton(AF_INET, server_ip, &server_addr.sin_addr)) < 0)
    goto cleanup;

  if ((ret = connect(sock, (struct sockaddr *)&server_addr,
                     sizeof(server_addr))) < 0)
    goto cleanup;

  if ((ret = fd = open(fname, O_RDONLY)) < 0)
    goto cleanup;

  // Compute deadline.
  struct timespec wall;
  uint64_t wall_ns, dead_ns;
  if (clock_gettime(CLOCK_REALTIME, &wall) < 0)
    return -1;
  wall_ns = 1000000000 * wall.tv_sec + wall.tv_nsec;
  dead_ns = latency_ns + wall_ns;
#ifdef DEBUG
  printf("deadline_ns: %lu\n", dead_ns);
#endif

  // Send file with timestamp.
  char buffer[BUFFER_SIZE];
  ssize_t bytes_read;
  while ((bytes_read = read(fd, buffer, sizeof(buffer))) > 0) {
    if (clock_gettime(CLOCK_REALTIME, &wall) < 0)
      return -1;
    wall_ns = 1000000000 * wall.tv_sec + wall.tv_nsec;
#ifdef DEBUG
    printf("wall_ns: %lu\n", wall_ns);
#endif
    if ((ret = send_with_timestamp(sock, buffer, bytes_read, wall_ns,
                                   dead_ns)) < 0)
      goto cleanup;
  }

  if ((ret = bytes_read) < 0)
    goto cleanup;

cleanup:
  close(fd);
  close(sock);

#ifdef DEBUG
  if (ret < 0)
    printf("Error during send with timestamp\n");
#endif

  return ret;
}
