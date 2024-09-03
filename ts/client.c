#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#define IP_ADDR "30.0.9.48"
#define PORT 2399
#define BUFFER_SIZE 1024
#define HEADER_SIZE 8
#define CHUNK_SIZE (BUFFER_SIZE - HEADER_SIZE)
#define AF21 18

int send_file_with_timestamp(int sock, FILE *file) {
  int ret = 0;
  char buffer[BUFFER_SIZE];
  char header[HEADER_SIZE];
  struct timespec wall;
  int64_t wall_ns;

  size_t read_size;
  while ((read_size = fread(buffer + HEADER_SIZE, 1, CHUNK_SIZE, file)) > 0) {
    if ((ret = clock_gettime(CLOCK_REALTIME, &wall)) < 0)
      return ret;

    wall_ns = 1000000000 * wall.tv_sec + wall.tv_nsec;
    memcpy(buffer, &wall_ns, HEADER_SIZE);

    if ((ret = send(sock, buffer, HEADER_SIZE + read_size, 0)) < 0) {
      close(sock);
      return ret;
    }
  }

  if (ferror(file)) {
    close(sock);
    return 1;
  }

  return 0;
}

int main(int argc, char *argv[]) {
  int ret = 0;
  int sock;
  struct sockaddr_in addr;
  FILE *file;
  char *filename;

  if (argc != 2) {
    fprintf(stderr, "Usage: %s <filename>\n", argv[0]);
    return 1;
  }

  filename = argv[1];

  file = fopen(filename, "rb");
  if (!file)
    return 1;

  sock = socket(AF_INET, SOCK_STREAM, 0);
  if ((ret = sock) < 0)
    goto cleanup;

  int dscp = AF21 << 2;
  if ((ret = setsockopt(sock, IPPROTO_IP, IP_TOS, &dscp, sizeof(dscp))) < 0)
    goto cleanup;

  memset(&addr, 0, sizeof(addr));
  addr.sin_family = AF_INET;
  addr.sin_port = htons(PORT);
  if ((ret = inet_pton(AF_INET, IP_ADDR, &addr.sin_addr)) <= 0)
    goto cleanup;

  if ((ret = connect(sock, (struct sockaddr *)&addr, sizeof(addr))) < 0)
    goto cleanup;

  ret = send_file_with_timestamp(sock, file);

cleanup:
  close(sock);
  fclose(file);

  return ret;
}
