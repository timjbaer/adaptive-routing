#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#ifndef MAX_ENTRIES
#	define MAX_ENTRIES 64
#endif

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
	// Lookup at key 0.
	__u32 k, *v;

	k = 0;
	v = bpf_map_lookup_elem(&intf_scores, &k);
	if (!v) {
		bpf_printk("error during bpf lookup map\n");
		return 0;
	}
	bpf_printk("key: %u, score: %u\n", k, *v);

	// Redirect packet to tunnel.
	// return bpf_redirect(ifindex, 0);
	return 0;
}

