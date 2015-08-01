/*
Portions are Copyright 2002 Tim Carstens. All rights reserved. 
Redistribution and use, with or without modification, are permitted provided
that the following conditions are met:

- Redistribution must retain the above copyright notice and this list of 
  conditions.

- The name of Tim Carstens may not be used to endorse or promote products
  derived from this document without specific prior written permission.
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <inttypes.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <netinet/in.h>
#include <pcap.h>

#define DEBUG 0

/* ethernet headers are always exactly 14 bytes */
/* XXX: ^^^ really? */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
/*
struct sniff_ethernet
{
  u_char ether_dhost[ETHER_ADDR_LEN]; / * Destination host address * /
  u_char ether_shost[ETHER_ADDR_LEN]; / * Source host address * /
  u_short ether_type; / * IP? ARP? RARP? etc * /
};
*/

/* IP header */
struct sniff_ip
{
  u_char ip_vhl;		/* version << 4 | header length >> 2 */
  u_char ip_tos;		/* type of service */
  u_short ip_len;		/* total length */
  u_short ip_id;		/* identification */
  u_short ip_off;		/* fragment offset field */
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */
  u_char ip_ttl;		/* time to live */
  u_char ip_p;		/* protocol */
  u_short ip_sum;		/* checksum */
  struct in_addr ip_src,ip_dst; /* source and dest address */
};
#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)

/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp
{
  u_short th_sport;	/* source port */
  u_short th_dport;	/* destination port */
  tcp_seq th_seq;		/* sequence number */
  tcp_seq th_ack;		/* acknowledgement number */
  u_char th_offx2;	/* data offset, rsvd */
#define TH_OFF(th)	(((th)->th_offx2 & 0xf0) >> 4)
  u_char th_flags;
#define TH_FIN 0x01
#define TH_SYN 0x02
#define TH_RST 0x04
#define TH_PUSH 0x08
#define TH_ACK 0x10
#define TH_URG 0x20
#define TH_ECE 0x40
#define TH_CWR 0x80
#define TH_FLAGS (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
  u_short th_win;		/* window */
  u_short th_sum;		/* checksum */
  u_short th_urp;		/* urgent pointer */
};

typedef struct {
  uint8_t kind;
  uint8_t size;
} tcp_option_t;



struct in_addr my_ip_raw;
struct in_addr target_ip_raw;
uint16_t target_port;

FILE* output;

struct useful_info
{
  uint32_t tcpseq;
  uint32_t tcpack;
  uint32_t tsval;
  uint16_t local_port;
  uint16_t payload_len;
  uint8_t sent;
};


char* output_template = "{\"local_port\":%u,\"sent\":%u,\"payload_len\":%u,\"tcpseq\":%u,\"tcpack\":%u,\"observed\":%lu%06lu000,\"tsval\":%u}\n";
uint8_t payloads_only = 1;


pcap_t* create_listener(const char* dev, int snaplen, int promisc, int to_ms, char* errbuf)
{
  pcap_t* ret_val;
  int status;
  int tstcount, i, besttst;
  int* tstypes;

  ret_val = pcap_create(dev, errbuf);
  if (ret_val == NULL)
    return (NULL);
  
  status = pcap_set_snaplen(ret_val, snaplen);
  if (status < 0)
    goto fail;
  
  status = pcap_set_promisc(ret_val, promisc);
  if (status < 0)
    goto fail;
  
  status = pcap_set_timeout(ret_val, to_ms);
  if (status < 0)
    goto fail;


  /* Try to select the best timestamp source for packet capture */
  tstcount = pcap_list_tstamp_types(ret_val, &tstypes);
  if(tstcount > 0)
  {
#if DEBUG
    fprintf(stderr, "INFO: Available Packet Timers: ");
#endif
    besttst = -1;
    for(i=0; i < tstcount; i++)
    {
#if DEBUG
        fprintf(stderr, " %s", pcap_tstamp_type_val_to_name(tstypes[i]));
#endif
      switch (tstypes[i])
      {
      case PCAP_TSTAMP_HOST:
        break;
      case PCAP_TSTAMP_HOST_LOWPREC:
        break;
      case PCAP_TSTAMP_HOST_HIPREC:
        {
          if(besttst != PCAP_TSTAMP_ADAPTER_UNSYNCED
             && besttst != PCAP_TSTAMP_ADAPTER)
            besttst = PCAP_TSTAMP_HOST_HIPREC;
          break;
        }
      case PCAP_TSTAMP_ADAPTER:
        {
          if(besttst != PCAP_TSTAMP_ADAPTER_UNSYNCED)
            besttst = PCAP_TSTAMP_ADAPTER;
          break;
        }
      case PCAP_TSTAMP_ADAPTER_UNSYNCED:
          /*besttst = PCAP_TSTAMP_ADAPTER_UNSYNCED;*/
          break;
      default:
#if DEBUG
          fprintf(stderr, " unknown_type_%d", tstypes[i]);
#endif
        break;
      }
    }
    pcap_free_tstamp_types(tstypes);
#if DEBUG
    fprintf(stderr, "\n");
#endif
    /*besttst = PCAP_TSTAMP_HOST;*/
    if(besttst != -1)
    {
#if DEBUG
      fprintf(stderr, "INFO: Attempting to set the timestamp source to: %s\n",
              pcap_tstamp_type_val_to_name(besttst));
#endif
      if(pcap_set_tstamp_type(ret_val, besttst) != 0)
        fprintf(stderr, "WARN: Failed to set preferred timestamp source.\n");
    }
  }
  
  /* Attempt to set nanosecond timestamp precision */    
  if(pcap_set_tstamp_precision(ret_val, PCAP_TSTAMP_PRECISION_NANO) != 0)
    fprintf(stderr, "INFO: Failed to set packet capture nanosecond precision.\n");
  else
    output_template = "{\"local_port\":%u,\"sent\":%u,\"payload_len\":%u,\"tcpseq\":%u,\"tcpack\":%u,\"observed\":%lu%09lu,\"tsval\":%u}\n";


  status = pcap_activate(ret_val);
  if (status < 0)
    goto fail;
  
  return ret_val;

 fail:
  pcap_close(ret_val);
  return NULL;
}


static int extract_packet_fields(const struct pcap_pkthdr *header,
                                 const u_char* packet,
                                 struct useful_info* fields)
{
  const struct sniff_ip* ip;               /* The IP header */
  const struct sniff_tcp* tcp;             /* The TCP header */
  u_int iphdr_size;
  u_int tcphdr_size;
  uint16_t ip_len;
  uint16_t tsval;
  uint8_t* opt;
  tcp_option_t* _opt;
  
  /*printf("snaplen: %u\n", header->caplen);*/
  
  ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  iphdr_size = IP_HL(ip)*4;
  if (iphdr_size < 20)
    return 0;
  ip_len = ntohs(ip->ip_len);
  
  tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + iphdr_size);
  tcphdr_size = TH_OFF(tcp)*4;
  if (tcphdr_size < 20)
    return 0;

  /*fprintf(stderr, "%d\n", (ip_len - iphdr_size - tcphdr_size));*/
  if ((ip_len - iphdr_size - tcphdr_size < 0)
      || (payloads_only && (ip_len - iphdr_size - tcphdr_size == 0)))
  { return 0; }

  fields->tcpseq = ntohl(tcp->th_seq);
  fields->tcpack = ntohl(tcp->th_ack);
  fields->payload_len = ip_len - iphdr_size - tcphdr_size;
  if(ip->ip_src.s_addr == target_ip_raw.s_addr && ntohs(tcp->th_sport) == target_port)
  {
    fields->sent = 0;
    fields->local_port = ntohs(tcp->th_dport);
  }
  else
  {
    fields->sent = 1;
    fields->local_port = ntohs(tcp->th_sport);
  }
  /*printf("src: %lX / dst: %lX\n", ip->ip_src, ip->ip_dst);*/

  fields->tsval = 0;
  if(tcphdr_size > 20)
  {
    opt = (uint8_t*)(packet + SIZE_ETHERNET + iphdr_size + 20);
    while((*opt != 0) && (opt - packet) < header->caplen)
    {
      _opt = (tcp_option_t*)opt;
      if(_opt->kind == 1) /* NOP */
      {
        ++opt;  // NOP is one byte;
        continue;
      }
      
      if(_opt->kind == 8) /* timestamp */
      {
        fields->tsval = ntohl(*(uint32_t*)(opt+2));
        break;
      }
      
      opt += _opt->size;
    }
  }

  return 1;
}


void process_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  struct useful_info fields;

  if(extract_packet_fields(header, packet, &fields))
  {
    fprintf(output, output_template, fields.local_port, fields.sent,
            fields.payload_len, fields.tcpseq, fields.tcpack,
            header->ts.tv_sec, header->ts.tv_usec, fields.tsval);
    fflush(output);
  }
}



int main(int argc, char** argv)
{
  char* dev;                      /* The device to sniff on */
  char* my_ip;
  char* target_ip;
  pcap_t* handle;                 /* Session handle */
  char bpf[255];                  /* The filter expression (length of 168 should be enough)*/
  char errbuf[PCAP_ERRBUF_SIZE];  /* Error string */
  struct bpf_program fp;          /* The compiled filter */
  bpf_u_int32 mask;               /* Our netmask */
  bpf_u_int32 net;                /* Our IP */
  struct pcap_pkthdr header;      /* The header that pcap gives us */
  const u_char *packet;           /* The actual packet */
    
  if(argc < 6)
  {
    fprintf(stderr, "USAGE:\n  %s {interface} {my_ip} {target_ip} {target_port} {output_file} [{payloads_only?}]\n", argv[0]);
    return 1;
  }

  dev = argv[1];
  my_ip = argv[2];
  target_ip = argv[3];
  target_port = atoi(argv[4]);
  if(argc == 7 && argv[6][0] == '0')
    payloads_only = 0;
  
  if(!(output = fopen(argv[5], "w+")))
  {
    fprintf(stderr, "ERROR: could not open output file due to: %s\n", strerror(errno));
    return 2;
  }
  
  snprintf(bpf, 255, "(src host %s and dst host %s and tcp and src port %u) or (dst host %s and src host %s and tcp and dst port %u)",
           target_ip, my_ip, target_port, target_ip, my_ip, target_port);


  if(!inet_aton(my_ip, &my_ip_raw))
  {
    fprintf(stderr, "Couldn't parse my_ip.\n");
    return 1;
  }

  if(!inet_aton(target_ip, &target_ip_raw))
  {
    fprintf(stderr, "Couldn't parse target_ip.\n");
    return 1;
  }

  memset(errbuf, 0, PCAP_ERRBUF_SIZE);

  /* Find the properties for the device */
  if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
  {
    fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev, errbuf);
    net = 0;
    mask = 0;
  }
  
  /* Open the session in promiscuous mode */
  /* XXX: does to_ms timeout (param 4) matter? */
  handle = create_listener(dev, BUFSIZ, 0, 1000, errbuf);
  if (handle == NULL)
  {
    fprintf(stderr, "Couldn't open device %s: %s\n", dev, errbuf);
    return 2;
  }

  /* Compile and apply the filter */
  if (pcap_compile(handle, &fp, bpf, 0, net) == -1)
  {
    fprintf(stderr, "Couldn't parse filter %s: %s\n", bpf, pcap_geterr(handle));
    return 2;
  }
  
  if (pcap_setfilter(handle, &fp) == -1)
  {
    fprintf(stderr, "Couldn't install filter %s: %s\n", bpf, pcap_geterr(handle));
    return 2;
  }

  /* XXX: report errors */
  pcap_loop(handle, 0, process_packet, NULL);
  
  /* And close the session */
  pcap_close(handle);

  return 0;
}
