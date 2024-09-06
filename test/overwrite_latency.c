#include <time.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define GRE1_INTF_IDX 6
#define GRE2_INTF_IDX 7
#define SLEEP_MS 50

struct latency_ns {
  __u32 min;
  __u32 max;
  __u32 avg;
};

static const char MAP_PATH[] = "/sys/fs/bpf/tc/globals/intf_latency";

int main(int argc, char **argv) {
  printf("overwriting interface latency map\n");
  int fd, ret;
  ret = usleep(1000000);

  // Get pinned BPF map.
  fd = bpf_obj_get(MAP_PATH);
  if ((ret = fd) < 0)
    goto cleanup;

  struct latency_ns gre1_latency[9] = {
      {10500, 10500, 10500}, {10500, 10500, 10500}, {10500, 10500, 10500},
      {10500, 10500, 10500}, {10500, 10500, 10500}, {10500, 10500, 10500},
      {10000, 10000, 10000}, {10500, 10500, 10500}, {10500, 10500, 10500},
  };
  struct latency_ns gre2_latency[9] = {
      {10600, 10600, 10600}, {10400, 10400, 10400}, {10600, 10600, 10600},
      {10000, 10000, 10000}, {10600, 10600, 10600}, {10400, 10400, 10400},
      {10600, 10600, 10600}, {10400, 10400, 10400}, {10600, 10600, 10600},
  };
  for (int i = 0; i < 9; ++i) {
    __u32 k1 = GRE1_INTF_IDX;
    ret = bpf_map_update_elem(fd, &k1, &gre1_latency[i], BPF_ANY);
    if (ret < 0)
      goto cleanup;
    __u32 k2 = GRE2_INTF_IDX;
    ret = bpf_map_update_elem(fd, &k2, &gre2_latency[i], BPF_ANY);
    if (ret < 0)
      goto cleanup;
    ret = usleep(SLEEP_MS * 1000);
    if (ret < 0)
      goto cleanup;
  }

cleanup:
  if (ret < 0)
    printf("error\n");
  printf("cleaning up\n");
  close(fd);
  return ret;
}
