#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#define MAX_ENTRIES 64
#define GRE1_INTF_IDX 6
#define TCP_TIMESTAMP_OFF 4
#define TCP_OPTIONS_LEN 12

char _license[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, __u32);
	__type(value, __u32);
	__uint(max_entries, MAX_ENTRIES);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} intf_scores SEC(".maps");

SEC("adapt_redir")
int _adapt_redir(struct __sk_buff *skb)
{
	// Parse custom timestamp.
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

	__u64 end_ns = bpf_ktime_get_ns();
	__u64 lat_ms = (end_ns - start_ns) / 1000000;
	bpf_printk("observed latency (ms): %llu\n", lat_ms);

	// Lookup at key 0.
	__u32 k, *v;

	k = 0;
	v = bpf_map_lookup_elem(&intf_scores, &k);
	if (!v) {
		bpf_printk("error during bpf lookup map\n");
		goto cleanup;
	}
	bpf_printk("key: %u, score: %u\n", k, *v);

cleanup:
	// Redirect packet to tunnel.
	return bpf_redirect_neigh(GRE1_INTF_IDX, NULL, 0, 0);
}

