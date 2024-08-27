#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#define MAX_ENTRIES 64
#define AF21_HEX 0x48
#define TCP_TIMESTAMP_OFF 4
#define TCP_OPTIONS_LEN 12
#define GRE1_INTF_IDX 6

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} intf_scores SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 1);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} boot_to_wall_off_ns SEC(".maps");

SEC("tc")
int adapt_redir(struct __sk_buff *skb)
{
	// Find IP header.
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

	// Only apply algorithm to low latency packets
	// defined as DSCP value AF21_HEX.
	if ((iph->tos & 0xFC) != AF21_HEX)
		goto cleanup;

	// Find TCP header.
	struct tcphdr *tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
        if (tcph + 1 > data_end)
		goto cleanup;

        if ((char*)(tcph + 1) + TCP_OPTIONS_LEN > data_end)
		goto cleanup;

	// Find TCP timestamp
        char *tcpts = (char*)(tcph + 1) + TCP_TIMESTAMP_OFF;
	__u64 start_ns = *(__u64*)tcpts;

	// Read boot to wall time offset from userspace.
        __u32 k = 0;
	__u64 *off_ns;
        off_ns = bpf_map_lookup_elem(&boot_to_wall_off_ns, &k);
        if (!off_ns)
                goto cleanup;

	// Compute latency.
	__u64 end_ns = bpf_ktime_get_boot_ns() + *off_ns;
	__u64 lat_ns = end_ns - start_ns;
	bpf_printk("observed latency (ns): %lu\n", lat_ns);

	// Lookup at key 0.
	__u32 *score;

	k = 0;
	score = bpf_map_lookup_elem(&intf_scores, &k);
	if (!score)
		goto cleanup;

cleanup:
	// Redirect packet to tunnel.
	return bpf_redirect_neigh(GRE1_INTF_IDX, NULL, 0, 0);
}

