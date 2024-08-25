#include <string.h>

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

#define ENS5_INTF_IDX 2
#define TCP_TIMESTAMP_OFF 4
#define TCP_OPTIONS_LEN 12

char _license[] SEC("license") = "GPL";

struct {
        __uint(type, BPF_MAP_TYPE_ARRAY);
        __type(key, __u32);
        __type(value, __u64);
        __uint(max_entries, 1);
        __uint(pinning, LIBBPF_PIN_BY_NAME);
	__uint(flags, BPF_F_MMAPABLE);
} boot_to_wall_off_ns SEC(".maps");

SEC("tc")
int set_timestamp(struct __sk_buff *skb)
{
	// Read boot to wall time offset from userspace.
        __u32 k = 0;
	__u64 *off_ns;
        off_ns = bpf_map_lookup_elem(&boot_to_wall_off_ns, &k);
        if (!off_ns)
                goto cleanup;

	// Find pointer to TCP timestamp option.
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

	// Override TCP timestamp with (synchronized) wall time.
	__u64 ts = bpf_ktime_get_boot_ns() + *off_ns;
	memcpy(tcpts, &ts, sizeof(__u64));

cleanup:
	return bpf_redirect_neigh(ENS5_INTF_IDX, NULL, 0, 0);
}

