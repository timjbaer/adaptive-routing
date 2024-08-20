#include <string.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>

// #include <linux/in.h>
#include <netinet/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

#define ENS5_INTF_IDX 2
#define TCP_TIMESTAMP_OFF 4
#define TCP_OPTIONS_LEN 12

char _license[] SEC("license") = "GPL";

SEC("ts")
int _ts(struct __sk_buff *skb)
{
	void *data = (void*)(long)skb->data;
	struct ethhdr *eth = data;
	void *data_end = (void*)(long)skb->data_end;

	if (data + sizeof(*eth) > data_end)
		return TC_ACT_OK;

	struct iphdr *iph = data + sizeof(*eth);

	if (iph + 1 > data_end)
		return TC_ACT_OK;

	if (iph->protocol != IPPROTO_TCP)
		return TC_ACT_OK;

	struct tcphdr *tcph = (struct tcphdr*)((__u32*)iph + iph->ihl);
	if (tcph + 1 > data_end)
		return TC_ACT_OK;

	if ((char*)(tcph + 1) + TCP_OPTIONS_LEN > data_end)
		return TC_ACT_OK;

	char *tcpts = (char*)(tcph + 1) + TCP_TIMESTAMP_OFF;
	bpf_printk("ts val: %u\n", htonl(*(__u32*)tcpts));

	// Override TS val and ecr with (synchronized) system time.
	// __u64 ts = bpf_ktime_get_ns();
	// memcpy(tcpts, &ts, sizeof(__u64));

	return bpf_redirect_neigh(ENS5_INTF_IDX, NULL, 0, 0);
}

