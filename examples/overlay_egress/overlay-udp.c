//go:build ignore
#include "linux/bpf.h"
#include "linux/if_ether.h"
#include "linux/ip.h"
#include "linux/in.h"
#include "linux/tcp.h"
#include "linux/udp.h"
#include "linux/pkt_cls.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

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

  //check IP header
  if (eth ->h_proto == bpf_htons(ETH_P_IP))
  {
    struct iphdr *iph = (struct iphdr *)(eth + 1);
    if ((void *)(iph + 1) > data_end)
    {
        return TC_ACT_OK;
    }
    
    //check UDP header
    if (iph->protocol == IPPROTO_UDP)
    {
      struct udphdr *udp = (struct udphdr *)(iph + 1);
      if ((void *)(udp + 1) > data_end)
      {
          return TC_ACT_OK;
      } 
  /*
      //bpf_printk("In the IP header,Source IP: %d",iph->saddr);
      bpf_printk("In the IP header,Source IPv4: %pI4",&(iph->saddr));
      // bpf_printk("In the IP header,Dest IP: %d",iph->daddr);
      bpf_printk("In the IP header,Dest IPv4: %pI4",&(iph->daddr));
      bpf_printk("In the IP header,ID : %d",iph->id);
    
      bpf_printk("In the UDP header,Source port: %d",bpf_htons(udp->source));
      bpf_printk("In the UDP header,Dest port: %d",bpf_htons(udp->dest));
  */
      if( bpf_htons(udp->dest) == 6081)
      {
        bpf_printk("In the IP header,Source IPv4: %pI4",&(iph->saddr));
        bpf_printk("In the IP header,Dest IPv4: %pI4",&(iph->daddr));
        bpf_printk("In the UDP header,Source port: %d",bpf_htons(udp->source));
        bpf_printk("In the UDP header,Dest port: %d",bpf_htons(udp->dest));
        unsigned int key;
        key = iph->daddr;
        unsigned int *ifindex;
        ifindex = bpf_map_lookup_elem(&ifindex_map, &key);
        if (ifindex)
        {
            bpf_printk("In the ifindex Map,ip:%pI4, ifindex:%d",&key,*ifindex);
            return bpf_redirect(*ifindex,0);
            //return bpf_redirect(26,1);
        }
        else
        {
          bpf_printk("Cant find ip:%pI4 in the ifindex Map,intIP:%d",&key,key);
        }
    
      }
    
    }

  }
  
  return TC_ACT_OK;
}
