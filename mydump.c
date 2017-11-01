//
//  main.c
//  NS_A2.1
//
//  Created by Ritu Prajapati on 9/27/17.
//  Copyright © 2017 Ritu Prajapati. All rights reserved.
//

#include <stdio.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <string.h>
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/ip6.h>
#include <ctype.h>
#include <stdlib.h>
#include <unistd.h>
#include <time.h>
#include <netinet/if_ether.h>
#include <netinet/in.h>

#define IP 1
#define ARP 2
#define TCP 3
#define UDP 4
#define ICMP 5
#define UNK 6

void my_packet_handler( u_char *, const struct pcap_pkthdr *, const u_char *);
int main(int argc, const char * argv[]) {
    
    char err_buffer[PCAP_ERRBUF_SIZE];
    pcap_t *handle;
    int timeout = 10000, p;
    bpf_u_int32 subnet_mask, ip;
    struct bpf_program fp;
    const u_char *exp = NULL, *device = NULL, *file = NULL;
    char  *str = NULL;
    opterr = 0;

while((p = getopt(argc,(char * const *) argv, "i:s:r:")) != -1){
switch(p){
		case 'r':
                file = optarg;
                break;
            case 'i':
                device = optarg;
                break;
            case 's':
                str = optarg;
                break;
            case '?':
                printf("Please provide valid arguments \n");
                return 1;
		      break;
            default:
                return -1;
}
}

    if(optind == argc - 1) 
		exp = argv[optind];

    if(file && device){
        printf("Error: Cannot capture in offline and online mode simultaneously\n");
        return 1;
    }
    
    if(file != NULL){
        handle = pcap_open_offline(file, err_buffer);
    }
    else if(device != NULL){
        handle = pcap_open_live(device, BUFSIZ, 0, timeout, err_buffer);
    }
    else
    {
        device = pcap_lookupdev(err_buffer);
        if(device == NULL) {
            printf("Error: Couldn't find default device: %s\n", err_buffer);
            exit(EXIT_FAILURE);
        }
        handle = pcap_open_live(device, BUFSIZ, 0, timeout, err_buffer);
    }
    
    
    if (handle == NULL){
        printf("Could not open device %s: %s\n", device, err_buffer);
        return 2;
    }
    

    if (pcap_lookupnet(device, &ip, &subnet_mask, err_buffer) == -1) {
        printf("Could not get information for device: %s\n", device);
        ip = 0;
        subnet_mask = 0;
    }
    

    if(exp != NULL){
        if(pcap_compile(handle, &fp, exp, 0, ip) == -1) {
            printf("Bad filter\n");
            return 2;
        }
        if(pcap_setfilter(handle, &fp) == -1) {
            printf("Error setting filter\n");
            return 2;
        }
    }
    

    pcap_loop(handle, 0, my_packet_handler, (u_char*)str);

    if (exp != NULL){
        pcap_freecode(&fp);
    }
    
    pcap_close(handle);
    return 0;
}

void print_time(const struct pcap_pkthdr *H){
    char timebuf[200];
    struct tm *time_tm;
    time_tm = localtime(&H->ts.tv_sec);
    strftime(timebuf, 200,"%Y-%m-%d %H:%M:%S", time_tm);
    printf("%s.%lu ", timebuf, (H->ts).tv_usec);
}
 
void print_MAC(u_char* ch){
for(int i = 0; i < ETHER_ADDR_LEN;){
        printf("%.2x", *ch);
	i++;
        if(i != ETHER_ADDR_LEN)  printf(":");
        ch++;
    }
}

void print_hex_ascii_line(const u_char *payload,int len,int offset)
{
    int i;
    int gap;
    const u_char *ch;
    
    ch = payload;
    for(i = 0; i < len;i++) {
        printf("%02x ",*ch);
        ch++;
    }
    /* print space to handle line less than 8 bytes */
    if(len < 8)
        printf(" ");
    
    /* fill hex gap with spaces if not full line */
    if(len < 20){
        gap = 20 - len;
        for (i = 0; i< gap;i++){
            printf("   ");
        }
    }
    printf("  ");
    
    /* ascii (if printable) */
    ch = payload;
    for(i=0;i<len;i++){
        if(isprint(*ch))
            printf("%c",*ch);
        else
            printf(".");
        ch++;
    }
    
    printf("\n");
    return;
}


void print_payload(const u_char *payload,int len){
    
    int len_rem = len;
    int line_width = 20;
    int line_len;
    int offset = 0;
    const u_char *ch = payload;
    
    if(len <= 0)
        return;
    
    /* data fits no one line */
    if (len <= line_width) {
        print_hex_ascii_line(ch,len,offset);
        return;
    }
    
    /* data spans multiple lines */
    for ( ; ;){
        
        line_len = line_width % len_rem;
        
        print_hex_ascii_line(ch,line_len,offset);
       
        len_rem = len_rem - line_len;
        
        ch = ch + line_len;
        
        offset = offset + line_width;
        
        if(len_rem <= line_width){
            
            print_hex_ascii_line(ch,len_rem,offset);
            break;
        }
    }
    return;
}

void my_packet_handler( u_char *args, const struct pcap_pkthdr *header, const u_char *packet){ 
   struct ether_header *eth_header;
   char sMAC[20], dMAC[20];
   uint16_t eth_type;

   int length;
   length = header->len;

    const struct ip *ip_header = NULL;
    struct ether_arp *arp_header;    
    const struct tcphdr *tcp_header = NULL;
    const struct udphdr *udp_header = NULL;
    const struct icmp *icmp_header = NULL;
 
    u_char *sIP, *dIP;
    struct in_addr address;
    struct in6_addr address6;
    u_char ip_protocol;
    char ip_protocol_str[10];
    int ip_length;


    eth_header = (struct ether_header *) (packet);
    eth_type = ntohs(eth_header->ether_type);
    int ethernet_length = 14;

    int net_proto = -1, trns_prt = -1;

    int srcport = 0;
    int destport = 0;
    
    int tcp_length;
    int udp_length;
    int icmp_length;
    int payload_length;
    int print_length;
    int arp_length;

    u_char * payload = NULL;
    int print = 0;
    switch(eth_type){
        case ETHERTYPE_IP:
	         net_proto = IP;
	         break;
        case ETHERTYPE_ARP:
	         net_proto = ARP;
	         break;
     }


if(net_proto == IP){
    ip_header = (struct ip*)(packet + ethernet_length);
    ip_length = (ip_header->ip_hl) * 4;
    switch(ip_header->ip_p){
                case IPPROTO_UDP:
                trns_prt = UDP;
                break;
                case IPPROTO_ICMP:
                trns_prt = ICMP;
                break;
                case IPPROTO_TCP:
                trns_prt = TCP;
                break;
                default:
                trns_prt = UNK;
                break;
}
    
switch(trns_prt){
case UDP:
            udp_header  = (struct udphdr*)(packet + ethernet_length + ip_length);
            srcport = ntohs(udp_header->uh_sport);
            destport = ntohs(udp_header->uh_dport);
	        udp_length = sizeof(udp_header);
	        payload_length = ntohs(ip_header->ip_len) - (ip_length + udp_length);
	        payload = (u_char*)(packet + ethernet_length);
	        print_length = length - ethernet_length;
	        break;

case TCP:
            tcp_header = (struct tcphdr*)((u_char *) ip_header+ ip_length);
            srcport = ntohs(tcp_header->th_sport);
            destport = ntohs(tcp_header->th_dport);
            tcp_length = (tcp_header->th_off)*4;
            payload_length = ntohs(ip_header->ip_len) - (ip_length + tcp_length);
            print_length = length - ethernet_length;
            payload = (u_char*)(packet + ethernet_length);
            break;
case ICMP:
            icmp_header = (struct icmp*)((u_char *) ip_header+ ip_length);
            icmp_length = sizeof(icmp_header);
            payload_length = ntohs(ip_header->ip_len) - (ip_length + icmp_length);
            print_length = length - ethernet_length;
            payload = (u_char*)(packet + ethernet_length);

case UNK:
            payload_length = ntohs(ip_header->ip_len) - ip_length;
            print_length = length - ethernet_length;
            payload = (u_char*)(packet + ethernet_length);
            break;
}
}
else if(net_proto == ARP){
            arp_header = (struct ether_arp*)(packet + ethernet_length);
            arp_length = length - ethernet_length;
            payload_length = length - ethernet_length - 8;
            print_length = length - ethernet_length;
            payload = (u_char *)(packet + ethernet_length);
}

if(args != NULL){
	if(payload_length == 0 || payload == NULL) return;
        u_char *payload_string = (u_char *)malloc( print_length + 1);
        u_char* p = payload;
	int i = 0;
        for( i = 0; i < print_length; i++){
            if(isprint(*p))
                payload_string[i] = *p;
            else
                payload_string[i] = '.';
            p++;
        }
	payload_string[i] = '\0';
        if(strstr(payload_string, args)) print = 1;
	free(payload_string);
	if(print == 0) return;
 }
 
   print_time(header);
   print_MAC(eth_header->ether_shost);
   printf(" > ");
   print_MAC(eth_header->ether_dhost);
   printf(" Ethertype ");
   if(net_proto == IP) printf("IP ");
   else if(net_proto == ARP) printf("ARP ");
   else printf("Unknown ");
   printf("( %#x ) Length: %d ", eth_type, length);
   
   if(net_proto == IP){
   printf("%s", inet_ntoa(ip_header->ip_src));
   if(srcport != 0) printf(":%d", srcport);
   printf(" > %s", inet_ntoa(ip_header->ip_dst));
   if(destport != 0) printf(":%d", destport);

   switch(trns_prt){
	case TCP:
	printf(" TCP, Payload Length: %d\n", payload_length);
	break;
	case UDP:
	printf(" UDP, Payload Length: %d\n", payload_length);
	break;
	case ICMP:
	printf(" ICMP, Payload Length: %d\n", payload_length);
	break;
	case UNK:
	printf(" UNKNOWN, Payload Length: %d\n", payload_length);
	break;
   }
}

if(net_proto == ARP){
        sIP = arp_header->arp_spa;
        dIP = arp_header->arp_tpa;
        int type = ntohs(arp_header->arp_op);
	if(type == 2){
	    printf("Reply %d.%d.%d.%d is at ", sIP[0], sIP[1], sIP[2], sIP[3]);
            printf("%d.%d.%d.%d ", dIP[0], dIP[1],dIP[2], dIP[3]);
        }
	else if(type == 1){
       	   printf("Request who-has %d.%d.%d.%d ", dIP[0], dIP[1],dIP[2], dIP[3]);
	   printf("Tell %d.%d.%d.%d ", sIP[0], sIP[1], sIP[2], sIP[3]);
	}
	else{
	    printf("%d.%d.%d.%d > ", sIP[0], sIP[1], sIP[2], sIP[3]);
            printf("%d.%d.%d.%d ", dIP[0], dIP[1],dIP[2], dIP[3]);
	}
        printf("Length: %d\n", arp_length);
}

   if (print_length > 0 && payload != NULL) {
        print_payload(payload, print_length);
    }
  printf("\n");
}

