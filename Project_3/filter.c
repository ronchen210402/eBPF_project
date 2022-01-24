#define KBUILD_MODNAME "filter"
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/udp.h>
#include <linux/tcp.h>

int xdpfilter(struct xdp_md *ctx) {
  bpf_trace_printk("\n");
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct ethhdr *eth = data;
  if ((void*)eth + sizeof(*eth) <= data_end) {
    struct iphdr *ip = data + sizeof(*eth); //boris: Make a ip header pointer from the origial received data packet.
    struct ipv6hdr *ipv6Header = data + sizeof(*eth); //boris: Make a ipv6 header pointer from the origial received data packet.
    //struct ip_auth_hdr *ip66 = data + sizeof(*eth);
    //struct ip_comp_hdr *ip666 = data + sizeof(*eth);
    //struct ip_beet_hdr *ip6666 = data + sizeof(*eth);
    //bpf_trace_printk("pass ip!\n");
    if ((void*)ip + sizeof(*ip) <= data_end) {
      if ((ip->version == 4) &&  (ip->protocol == IPPROTO_UDP)) {  //boris: That means, it's a IPv4 packet and a UDP packet.
        struct udphdr *udp = (void*)ip + sizeof(*ip); //boris: Make a UDP header pointer.
        bpf_trace_printk("Packet : IPv4 & UDP\n");
        if ((void*)udp + sizeof(*udp) <= data_end) {
          if (udp->dest == ntohs(7999)) { 
            bpf_trace_printk("UDP, originally aimed at port 7999, now changed to 7998.\n");
            bpf_trace_printk("We let it pass.\n");
            udp->dest = ntohs(7998); //boris: Change packet's destination!
          }
        }
      }
      if ((ip->version == 4) &&  (ip->protocol == IPPROTO_TCP)) {  //boris: That means, it's a IPv4 packet and a TCP packet.
        struct tcphdr *tcp = (void*)ip + sizeof(*ip);//boris: Make a TCP header pointer.
        bpf_trace_printk("Packet : IPv4 & TCP\n");
        if ((void*)tcp + sizeof(*tcp) <= data_end) {
          if (tcp->dest == ntohs(7999)) { 
            bpf_trace_printk("TCP, originally aimed at port 7999, remains unchanged, still to 7999.\n");
            //tcp->dest = ntohs(7997);
            bpf_trace_printk("We let it pass.\n"); //boris: We consider TCP packets to be unharmful, so we don't change TCP packets' destinations.
          }
        }
      }
      if (ip->version == 6) {  //boris: That means, it's a IPv6 packet.
        
        if (ipv6Header->nexthdr==17) { //boris: 17 is the protocal number of UDP packets.
          bpf_trace_printk("Packet : IPv6 & UDP\n");
          bpf_trace_printk("We gonna drop it!\n");  //boris: We consider our "server" is quite old, so that it doesn't want to receive any IPv6 packet.
          //bpf_trace_printk("size of eth:%u!\n", sizeof(*eth));
          //bpf_trace_printk("size of ip:%u\n", sizeof(*ip));
          //bpf_trace_printk("size of data[56]:%s\n", ((char*)(data))[56]);
          //bpf_trace_printk("size of data[57]:%s\n", ((char*)(data))[57]);
          //bpf_trace_printk("udpv6->dest:%u\n", *dport);
          return XDP_DROP;
        }
        if (ipv6Header->nexthdr==6) { ////boris: 6 is the protocal number of TCP packets.
          bpf_trace_printk("Packet : IPv6 & TCP\n");
          bpf_trace_printk("We gonna drop it!\n"); //boris: We consider our "server" is quite old, so that it doesn't want to receive any IPv6 packet.
          return XDP_DROP;
        }
        //bpf_trace_printk("ipv6Header->nexthdr:%u\n", ipv6Header->nexthdr);
      }
  }
  return XDP_PASS;
}
}

