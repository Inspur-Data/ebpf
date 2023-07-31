//go:build ignore
#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/ip.h"
#include "linux/in.h"
#include "linux/tcp.h"
#include "linux/pkt_cls.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"
//#include "common.h"
#define AF_INET 2

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") ifindex_map = {
	.type        = BPF_MAP_TYPE_HASH,
	.key_size    = sizeof(unsigned int),
	.value_size  = sizeof(unsigned int),
	.max_entries = 256,
};

SEC("tc")
int tc_print(struct __sk_buff *skb)
{

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  //bpf_printk("In the skb header,ifindex: %d",skb->ifindex);
  struct ethhdr *eth = data;

  if ((void *)(eth + 1) > data_end) 
  {
      return TC_ACT_OK;
  }
  /*
  bpf_printk("In the eth header,source: %s",eth->h_source);
  bpf_printk("In the eth header,dest: %s",eth->h_dest);
  bpf_printk("In the eth header,protocol: %s",eth->h_proto);*/

  if (eth ->h_proto == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return TC_ACT_OK;
    }
    
    if (iph->protocol == IPPROTO_TCP)
    {
      struct tcphdr *tcp = (struct tcphdr *)(iph + 1);
      if ((void *)(tcp + 1) > data_end)
      {
          return TC_ACT_OK;
      } 


      if( bpf_htons(tcp->dest) == 8080)
      {
        bpf_printk("In the IP header,Source IPv4: %pI4",&(iph->saddr));
        bpf_printk("In the IP header,Dest IPv4: %pI4",&(iph->daddr));
        bpf_printk("In the IP header,ID : %d",iph->id);
      
        bpf_printk("In the TCP header,Source port: %d",bpf_htons(tcp->source));
        bpf_printk("In the TCP header,Dest port: %d",bpf_htons(tcp->dest));

        unsigned int key;
        key = iph->daddr;
        unsigned int *ifindex;
        ifindex = bpf_map_lookup_elem(&ifindex_map, &key);
        if (ifindex)
        {
          
            bpf_printk("In the ifindex Map,ip:%pI4, ifindex:%d",&key,*ifindex);
            return bpf_redirect_neigh(ifindex, &neighInfo, sizeof(neighInfo), 0);
        }
        else
        {
          bpf_printk("Cant find ip:%pI4 in the ifindex Map,intIP:%d,redirect_neigh to 26 for test",&key,key);
          //only for test
          struct bpf_redir_neigh neighInfo = {0};
          neighInfo.nh_family = AF_INET;
          neighInfo.ipv4_nh = iph->daddr;
          return bpf_redirect_neigh(26, &neighInfo, sizeof(neighInfo), 0);
        }       
      }
       
    }

  }
  
  return TC_ACT_OK;
}
