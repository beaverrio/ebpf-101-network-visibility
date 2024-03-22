//go:build ignore

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

#define IP_MF       0x2000
#define IP_OFFSET   0x1FFF
#define ETH_HLEN    14

// Taken from uapi/linux/tcp.h
struct __tcphdr {
	__be16  source;
	__be16  dest;
	__be32  seq;
	__be32  ack_seq;
	__u16   res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1, cwr : 1;
	__be16  window;
	__sum16 check;
	__be16  urg_ptr;
};

static inline int ip_is_fragment(struct __sk_buff *skb, __u32 nhoff) {
	__u16 frag_off;

	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, frag_off), &frag_off, 2);
	frag_off = __bpf_ntohs(frag_off);
	return frag_off & (IP_MF | IP_OFFSET);
}

// Define the byte order conversion for big-endian to host
#define be32toh(x) ((__u32)(x))

// Printing the received IP from __be32 into a human readble string
void print_be32_as_ip(__be32 ip, __u16 proto, __u32 ip_proto) {
    // Convert from big-endian to host byte order
    __u32 host_ip = be32toh(ip);

    // Extract the individual bytes
    __u8 byte1 = (host_ip >> 24) & 0xFF;
    __u8 byte2 = (host_ip >> 16) & 0xFF;
    __u8 byte3 = (host_ip >> 8) & 0xFF;
    __u8 byte4 = host_ip & 0xFF;

	bpf_printk("\t* Parsed IP %d.%d.%d.%d", byte4, byte3, byte2, byte1);
}

SEC("socket")
int socket_handler(struct __sk_buff *skb) {
	__u16 proto;
	__u32 nhoff   	= ETH_HLEN;
	
	bpf_skb_load_bytes(skb, 12, &proto, 2);
	proto = __bpf_ntohs(proto);
	if (proto != ETH_P_IP) {
		return 0;
    }

	if (ip_is_fragment(skb, nhoff)) {
		return 0;
    }

	__u8 hdr_len;
	// ip4 header lengths are variable
	// Access ihl as a u8 (linux/include/linux/skbuff.h)
	bpf_skb_load_bytes(skb, ETH_HLEN, &hdr_len, sizeof(hdr_len));
	hdr_len &= 0x0f;
	hdr_len *= 4;

	// Verify hlen meets minimum size requirements
	if (hdr_len < sizeof(struct iphdr)) {
		return 0;
	}

	__u32 ip_proto	= 0;
	bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, protocol), &ip_proto, 1);

    // Is it a TCP packet? Protocol field == 6
	if (ip_proto == IPPROTO_TCP) {
		bpf_printk("The packet was sent using protocol %d", ip_proto);
		
		__be32 src_address;
		__be32 dst_address;
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, saddr), &src_address, 4);
		bpf_skb_load_bytes(skb, nhoff + offsetof(struct iphdr, daddr), &dst_address, 4);
	
		__be16 ports[2];
		bpf_skb_load_bytes(skb, nhoff + hdr_len, &ports, 4);

		__le16 src_port = ports[0];
		__le16 dst_port = ports[1];
		// The ports are read as big endian. The following lines convert it to little endian.
		// e.g. port 8000 is represented as 1f40 but the actual data is 401f thus the bytes must be swapped.
		src_port = ((src_port>>8) | (src_port<<8));
		dst_port = ((dst_port>>8) | (dst_port<<8));

		bpf_printk("Packet was sent from:");
		print_be32_as_ip(src_address, proto, ip_proto);
		bpf_printk("\tFrom port: %d", src_port);
		bpf_printk("Its destination is:");
		print_be32_as_ip(dst_address, proto, ip_proto);
		bpf_printk("\tTo port: %d", dst_port);
	}
    
	return 0;
}