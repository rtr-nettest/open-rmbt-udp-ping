#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>

SEC("xdp")
int xdp_prog(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if (eth + 1 > data_end) return XDP_PASS;

    if (eth->h_proto != htons(ETH_P_IP)) return XDP_PASS;

    struct iphdr *iph = data + sizeof(*eth);
    if (iph + 1 > data_end) return XDP_PASS;

    if (iph->protocol != IPPROTO_UDP) return XDP_PASS;

    struct udphdr *udp = (void *)iph + sizeof(*iph);
    if (udp + 1 > data_end) return XDP_PASS;

    void *payload = (void *)udp + sizeof(*udp);
    if (payload + 14 > data_end) return XDP_PASS;

    if (__builtin_memcmp(payload, "RP01", 4) != 0 ||
        __builtin_memcmp(payload + 8, "testme", 6) != 0) {
        return XDP_PASS;
    }

    // Prepare response
    __builtin_memcpy(eth->h_dest, eth->h_source, ETH_ALEN);
    __builtin_memcpy(eth->h_source, "\x00\x00\x00\x00\x00\x00", ETH_ALEN);
    __builtin_memcpy(payload, "RR01", 4);

    return XDP_TX;
}

char _license[] SEC("license") = "GPL";