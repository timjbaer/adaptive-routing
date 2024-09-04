#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>

#define DEBUG 1
#define MAX_INTFS 16
#define AF21_HEX 0x48
#define ENS5_INTF_IDX 2
#define UINT32_MAX 0xFFFFFFFF

char _license[] SEC("license") = "GPL";

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(flags, BPF_F_MMAPABLE);
} boot_to_wall_off_ns SEC(".maps");

struct latency_ns {
  __u32 min;
  __u32 max;
  __u32 avg;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, struct latency_ns);
  __uint(max_entries, MAX_INTFS);
  __uint(pinning, LIBBPF_PIN_BY_NAME);
  __uint(flags, BPF_F_MMAPABLE);
} intf_latency SEC(".maps");

// Calling the BPF helper inline cannot be unrolled on clang 14.
struct latency_ns *lookup_latency(int k) {
  return bpf_map_lookup_elem(&intf_latency, &k);
}

SEC("tc")
int adapt_redir(struct __sk_buff *skb) {
  // Find IP header.
  void *data = (void *)(long)skb->data;
  struct ethhdr *eth = data;
  void *data_end = (void *)(long)skb->data_end;

  if (data + sizeof(*eth) > data_end)
    goto cleanup;

  struct iphdr *iph = data + sizeof(*eth);

  if (iph + 1 > data_end)
    goto cleanup;

  if (iph->protocol != IPPROTO_TCP)
    goto cleanup;

  // Only apply algorithm to low latency packets
  // defined as DSCP value AF21_HEX.
  if (iph->tos != AF21_HEX)
    goto cleanup;

  // Find TCP header.
  struct tcphdr *tcph = (struct tcphdr *)((__u32 *)iph + iph->ihl);
  if (tcph + 1 > data_end)
    goto cleanup;

  // Find timestamp and deadline.
  char *ts = (char *)tcph + tcph->doff * 4;
  if (ts + 2 * sizeof(__u64) > data_end)
    goto cleanup;

  __u64 start_ns = *(__u64 *)ts;
  __u64 dead_ns = *(__u64 *)(ts + sizeof(__u64));

  // Read boot to wall time offset from userspace.
  __u32 k = 0;
  __u64 *off_ns;
  off_ns = bpf_map_lookup_elem(&boot_to_wall_off_ns, &k);
  if (!off_ns)
    goto cleanup;

  __u64 end_ns = bpf_ktime_get_boot_ns() + *off_ns;

  // Compute latency.
  __u64 obs_ns = 0;
  if (end_ns > start_ns)
    obs_ns = end_ns - start_ns;
#ifdef DEBUG
  bpf_printk("start (ns): %lu\n", start_ns);
  bpf_printk("end (ns): %lu\n", end_ns);
  bpf_printk("deadline (ns): %lu\n", dead_ns);
  bpf_printk("observed latency (ns): %lu\n", obs_ns);
#endif

  // Adaptive routing algorithm.
  // TODO: add hyperparameter to follow same path if only a little worse.
  __u32 best_idx = ENS5_INTF_IDX;
  __u32 best_avg = UINT32_MAX;
#pragma clang loop unroll(full)
  for (__u32 k = 0; k < MAX_INTFS; k++) {
    struct latency_ns *v = lookup_latency(k);
    if (!v || v->avg == 0)
      continue;
#ifdef DEBUG
    bpf_printk("intf index: %d\n", k);
    bpf_printk("min intf latency (ns): %lu\n", v->min);
    bpf_printk("max intf latency (ns): %lu\n", v->max);
    bpf_printk("avg intf latency (ns): %lu\n", v->avg);
#endif
    // TODO: this is per-packet deadlines.
    if (v->max + obs_ns < dead_ns && v->avg < best_avg) {
      best_idx = k;
      best_avg = v->avg;
    }
  }

#ifdef DEBUG
  if (best_avg != UINT32_MAX)
    bpf_printk("routing through best interface: %d\n", best_idx);
  else
    bpf_printk("no interface can meet deadline\n");
#endif
  return bpf_redirect_neigh(best_idx, NULL, 0, 0);

cleanup:
#ifdef DEBUG
  bpf_printk("error with adaptive routing\n");
  bpf_printk("routing through ens5: %d\n", ENS5_INTF_IDX);
#endif
  return bpf_redirect_neigh(ENS5_INTF_IDX, NULL, 0, 0);
}
