#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>
#include "perfsonar_metrics.h"

#define MAX_ENTRIES 64
#define GRE1_INTF_IDX 2
#define TCP_TIMESTAMP_OFF 4
#define TCP_OPTIONS_LEN 12

char _license[] SEC("license") = "GPL";

// struct {
// 	//__uint(type, BPF_MAP_TYPE_ARRAY);
// 	__uint(type, BPF_MAP_TYPE_HASH);
// 	__type(key, __u32);
// 	__type(value, perfSonar);
// 	__uint(max_entries, MAX_ENTRIES);
// 	__uint(pinning, LIBBPF_PIN_BY_NAME);
// 	__uint(flags, BPF_F_MMAPABLE);
// } perfsonar_scores SEC(".maps");

struct {
	//__uint(type, BPF_MAP_TYPE_ARRAY);
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u64);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} perfsonar_scores SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 1);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} boot_to_wall_off_ns SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, 1);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} best_tunnel_map SEC(".maps");

SEC("tc")
int adapt_redir(struct __sk_buff *skb)
{
	// Read boot to wall time offset from userspace.
        __u32 k = 0;
		__u64 *off_ns;
        off_ns = bpf_map_lookup_elem(&boot_to_wall_off_ns, &k);
        if (!off_ns)
                goto cleanup;

	// Find TCP timestamp.
	void *data = (void*)(long)skb->data;
        struct ethhdr *eth = data;
        void *data_end = (void*)(long)skb->data_end;

        if (data + sizeof(*eth) > data_end)
		goto cleanup;

        struct iphdr *iph = data + sizeof(*eth);

        if (iph + 1 > data_end)
		goto cleanup;

        if (iph->protocol != IPPROTO_TCP)
		goto cleanup;

	        struct tcphdr *tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
        if (tcph + 1 > data_end)
		goto cleanup;

        if ((char*)(tcph + 1) + TCP_OPTIONS_LEN > data_end)
		goto cleanup;

        char *tcpts = (char*)(tcph + 1) + TCP_TIMESTAMP_OFF;
	__u64 start_ns = *(__u64*)tcpts;

	// Compute latency.
	__u64 end_ns = bpf_ktime_get_boot_ns() + *off_ns;
	__u64 lat_ns = end_ns - start_ns;
	//bpf_printk("observed latency (ms): %lu\n", lat_ns);

	int best_tunnel_key = 42;
	int *best_tunnel_val;

	// Lookup at key 42 where the best tunnel id is stored
	best_tunnel_val = bpf_map_lookup_elem(&best_tunnel_map, &best_tunnel_key);

	if (best_tunnel_val == 0)
		goto cleanup;
	else
		return bpf_redirect_neigh(*best_tunnel_val, NULL, 0, 0); // THIS HAS TO BE TUNNEL INTERFACE INDEX
	

cleanup:
	// Redirect packet to tunnel.
	return bpf_redirect_neigh(GRE1_INTF_IDX, NULL, 0, 0);
}

