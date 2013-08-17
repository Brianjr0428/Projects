#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdbool.h>
#include <netinet/if_ether.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


#define Ethernet           DLT_EN10MB
#define ETHERNET_SIZE      14
#define TCPOPT_EOL	   0
#define TCPOPT_NOP	   1
#define TCPOPT_MAXSEG      2
#define TCPOPT_WINDOW      3
#define TCPOPT_SACK_PERMITTED	4
#define TCPOPT_TIMESTAMP   8
#define TCPOPT_SACK                            5
#define TCPOPT_ECHO                            6
#define TCPOPT_ECHOREPLY               7

#define MAX_BUF_SIZE       20

#define IP_HL(ip)		(((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)		(((ip)->ip_vhl) >> 4)
#define IP_RF 0x8000		/* reserved fragment flag */
#define IP_DF 0x4000		/* dont fragment flag */
#define IP_MF 0x2000		/* more fragments flag */
#define IP_OFFMASK 0x1fff	/* mask for fragmenting bits */


typedef struct link_node{
       char value[MAX_BUF_SIZE];
       int number;
       struct link_node *next;
} Node;

typedef struct arp_node {
	char mac[MAX_BUF_SIZE];
	char ip[MAX_BUF_SIZE];
	struct arp_node *next;
} Arp_node;

struct sniff_ip {
	u_char ip_vhl;		/* version << 4 | header length >> 2 */
	u_char ip_tos;		/* type of service */
	u_short ip_len;		/* total length */
	u_short ip_id;		/* identification */
	u_short ip_off;		/* fragment offset field */
	u_char ip_ttl;		/* time to live */
	u_char ip_p;		/* protocol */
	u_short ip_sum;		/* checksum */
	struct in_addr ip_src,ip_dst; /* source and dest address */
};

struct tcphdr {
	u_int16_t	th_sport;	/* source port */
	u_int16_t	th_dport;	/* destination port */
	u_int32_t	th_seq;	/* sequence number */
	u_int32_t	th_ack;	/* acknowledgement number */
	u_int8_t	th_offx2;	/* data offset, rsvd */
	u_short  fin:1;
	u_short  syn:1;
	u_short  rst:1;
	u_short  psh:1;
	u_short  ack:1;
	u_short  urg:1;
	u_int16_t	th_win;	/* window */
	u_int16_t	th_sum;	/* checksum */
	u_int16_t	th_urp;	/* urgent pointer */
};

/* ARP Header, (assuming Ethernet+IPv4)            */ 
#define ARP_REQUEST 1   /* ARP Request             */ 
#define ARP_REPLY 2     /* ARP Reply               */ 
struct arp_hdr { 
    u_int16_t htype;    /* Hardware Type           */ 
    u_int16_t ptype;    /* Protocol Type           */ 
    u_char hlen;        /* Hardware Address Length */ 
    u_char plen;        /* Protocol Address Length */ 
    u_int16_t oper;     /* Operation Code          */ 
    u_char sha[6];      /* Sender hardware address */ 
    u_char spa[4];      /* Sender IP address       */ 
    u_char tha[6];      /* Target hardware address */ 
    u_char tpa[4];      /* Target IP address       */ 
}; 

#define TH_OFF(th) (((th)->th_offx2 & 0xf0) >> 4)

Node *transLayer = NULL, *TCP_src_ports = NULL, *TCP_dest_ports = NULL, *TCP_flags = NULL, *TCP_options = NULL, 
     *UDP_src_ports = NULL, *UDP_dest_ports = NULL,*ICMP_src_IP = NULL, *ICMP_dest_IP = NULL,*ICMP_TYPE = NULL, 
     *ICMP_CODE = NULL, *ICMP_RESPONSE = NULL, *net_layer = NULL, *IP_src_addr = NULL, *IP_dest_addr = NULL,
	 *TTL_list = NULL, *eth_src_addr = NULL, *eth_dest_addr = NULL;
int packets = 0, total_bytes=0, smallest_pkt = 10000, largest_pkt = 0, EOL_count=0 , 
           NOP_count=0, MAXSEG_count=0, WINDOW_count=0, SACK_PERMITTED_count=0, TIMESTAMP_count=0, ip_packets=0,
           TCP_packets=0, UDP_packets=0, ICMP_packets=0;
struct timeval get_time, start_time;
char timebuffer[30];
long start, end, time_buffer_sec, time_buffer_usec, min=10000000000000000, max=0;
time_t start_date;


Arp_node *arp_participants;

Node* insert(Node *node, char* insert_value);
void print(char* category, Node *node, int total);
void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet);
void process_ip(const u_char* packet, const struct ether_header *ethernet, const struct sniff_ip *ip, const char *payload, u_int size_ip);
char* getTimeDiff(char* str);
void print_summary(char* timebuffer, struct timeval start_time, char* timeDuration);
void process_tcp(const u_char* packet, u_int size_ip);
void process_udp(const u_char* packet, u_int size_ip);
void process_icmp(const u_char* packet, u_int size_ip, const struct sniff_ip *ip);
void process_tcp_option(int hlen, const struct tcphdr *tcp_header);
char* get_icmp_response(int type, int code);
void print_arp(Arp_node* node);
Arp_node* insert_arp_node(Arp_node* node, char* mac, char* ip);
void free_arp_nodes(Arp_node *node);
void free_nodes(Node *node);

int main(int argc,char **argv) {
	pcap_t *pcap;
	char pcapErr[PCAP_ERRBUF_SIZE],  line[80] ;
	char* title;
	int datalink;
	char timeDuration[MAX_BUF_SIZE];
	char file_name[MAX_BUF_SIZE];

	if (argc != 2) {
		printf("Usage: ./wiretap file.pcap\n");
		printf("       ./wiretap file.pcap > output.txt\n");
		exit(1);
	}
	
	strcpy(file_name, argv[1]);
	pcap = pcap_open_offline(file_name, pcapErr);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_offline failed: %s\n", pcapErr);
		exit(EXIT_FAILURE);
	}

	datalink = pcap_datalink(pcap);

	if(datalink != Ethernet) {
		printf("not Ethernet!\n");
		exit(EXIT_FAILURE);
	}
	
	pcap_loop(pcap,-1,my_callback,NULL);

    getTimeDiff(timeDuration); 

	print_summary(timebuffer, start_time, timeDuration);
	printf("=== Link layer ===\n\n");
	print("Source ethernet addresses", eth_src_addr, packets);
	free_nodes(eth_src_addr);
	print("Destination ethernet addresses", eth_dest_addr, packets);
	free_nodes(eth_dest_addr);

	printf("=== Network Layer ===\n\n");
	print("Network layer protocols", net_layer, packets);
	free_nodes(net_layer);
	print("Source IP addresses", IP_src_addr, ip_packets);
	free_nodes(IP_src_addr);
	print("Destination IP addresses", IP_dest_addr, ip_packets);
	free_nodes(IP_dest_addr);
	print("TTLs",TTL_list, ip_packets);
	free_nodes(TTL_list);
	print_arp(arp_participants);
	free_arp_nodes(arp_participants);

	printf("=== Transport Layer ===\n\n");
	print("Transport Layer protocols", transLayer, ip_packets);
	free_nodes(transLayer);

	printf("=== Transport Layer: TCP ===\n\n");
	print("Source TCP ports", TCP_src_ports, TCP_packets);
	free_nodes(TCP_src_ports);
	print("Destination TCP ports", TCP_dest_ports, TCP_packets);
	free_nodes(TCP_dest_ports);
	print("TCP flags", TCP_flags, TCP_packets);
	free_nodes(TCP_flags);
	print("TCP options", TCP_options, TCP_packets);
	free_nodes(TCP_options);

	printf("=== Transport Layer: UDP ===\n\n");
	print("Source UDP ports", UDP_src_ports, UDP_packets);
	free_nodes(UDP_src_ports);
	print("Destination UDP ports", UDP_dest_ports, UDP_packets);
	free_nodes(UDP_dest_ports);

	printf("=== Transport Layer: ICMP ===\n\n");
	print("Source IPs for ICMP", ICMP_src_IP, ICMP_packets);
	free_nodes(ICMP_src_IP);
	print("Destination IPs for ICMP", ICMP_dest_IP, ICMP_packets);
	free_nodes(ICMP_dest_IP);
	print("ICMP types", ICMP_TYPE, ICMP_packets);
	free_nodes(ICMP_TYPE);
	print("ICMP codes", ICMP_CODE, ICMP_packets);
	free_nodes(ICMP_CODE);
	print("ICMP responses", ICMP_RESPONSE, ICMP_packets);
	free_nodes(ICMP_RESPONSE);
	pcap_close(pcap);
}

char* getTimeDiff(char* str){
    long h,m,s, us;  
    long dif = max - min;
    us = dif%1000000;
    dif /= 1000000;
    s = dif%60;
    dif /= 60;
    m = dif%60;
    dif /= 60;
    h = dif;
    sprintf(str, "%d:%02ld:%02ld:%ld", h, m, s, us);
	return str;
}

void my_callback(u_char *args,const struct pcap_pkthdr* pkthdr,const u_char* packet) {
	const struct ether_header *ethernet; /* The ethernet header */
	const struct sniff_ip *ip; /* The IP header */
	const char *payload; /* Packet payload */
	char buffer[MAX_BUF_SIZE];
	char ip_addr[MAX_BUF_SIZE];
	struct arp_hdr *arpheader = NULL;       /* Pointer to the ARP header */ 

	get_time = pkthdr->ts;
	time_buffer_usec = (long)get_time.tv_usec;
	time_buffer_sec = (long)get_time.tv_sec;
	time_buffer_usec += time_buffer_sec*1000000;
    
    if(time_buffer_usec < min){
       min = time_buffer_usec;
       start_time = get_time;
       strftime(timebuffer,30,"%Y-%m-%d %T.",localtime(&time_buffer_sec));
       }
    if(time_buffer_usec > max)
       max = time_buffer_usec;

    start_date=get_time.tv_sec;

	u_int size_ip;
	int len = pkthdr->len;
	packets++;
	total_bytes += len;
	if (len < smallest_pkt)
		smallest_pkt = len;

	if (len > largest_pkt)
		largest_pkt = len;   

	ethernet = (struct ether_header*)(packet);

	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int) ethernet->ether_dhost[0],
		(unsigned int) ethernet->ether_dhost[1], (unsigned int) ethernet->ether_dhost[2], 
		(unsigned int) ethernet->ether_dhost[3],(unsigned int) ethernet->ether_dhost[4],
		(unsigned int) ethernet->ether_dhost[5]); 
	eth_dest_addr = insert(eth_dest_addr, buffer); 
	//arp_participants = insert_arp_node(arp_participants, buffer, inet_ntoa(ip->ip_dst));

	sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int) ethernet->ether_shost[0],
		(unsigned int) ethernet->ether_shost[1], (unsigned int) ethernet->ether_shost[2], 
		(unsigned int) ethernet->ether_shost[3],(unsigned int) ethernet->ether_shost[4],
		(unsigned int) ethernet->ether_shost[5]); 
	eth_src_addr = insert(eth_src_addr, buffer); 
	//arp_participants = insert_arp_node(arp_participants, buffer, inet_ntoa(ip->ip_src));
	

	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP) {
		process_ip(packet, ethernet, ip, payload, size_ip);
		net_layer = insert(net_layer, "IP");
	} else if(ntohs (ethernet->ether_type) == ETHERTYPE_ARP) {
		net_layer = insert(net_layer, "ARP");
		arpheader = (struct arp_hdr *)(packet+14); /* Point to the ARP header */
		 /* If is Ethernet and IPv4, print packet contents */
		if (ntohs(arpheader->htype) == 1 && ntohs(arpheader->ptype) == 0x0800) {
			sprintf(buffer, "%02x:%02x:%02x:%02x:%02x:%02x", (unsigned int) arpheader->sha[0],
				(unsigned int) arpheader->sha[1], (unsigned int) arpheader->sha[2], 
				(unsigned int) arpheader->sha[3],(unsigned int) arpheader->sha[4],
				(unsigned int) arpheader->sha[5]);  

			sprintf(ip_addr, "%d.%d.%d.%d", arpheader->spa[0], arpheader->spa[1], arpheader->spa[2],
				arpheader->spa[3]);

			arp_participants = insert_arp_node(arp_participants, buffer, ip_addr);
		}
	} else {
		sprintf(buffer, "0x%04x", ntohs(ethernet->ether_type));
		net_layer = insert(net_layer, buffer);
	}
}

void process_ip(const u_char* packet, const struct ether_header *ethernet, const struct sniff_ip *ip, const char *payload, u_int size_ip){
	ip = (struct sniff_ip*)(packet + ETHERNET_SIZE);
	size_ip = IP_HL(ip)*4;
	ip_packets++;
	char buffer[MAX_BUF_SIZE];

	sprintf(buffer, "%s", inet_ntoa(ip->ip_src)); 
	IP_src_addr = insert(IP_src_addr, buffer); 
	sprintf(buffer, "%s", inet_ntoa(ip->ip_dst)); 
	IP_dest_addr = insert(IP_dest_addr, buffer); 

	sprintf(buffer, "%d", ip->ip_ttl); 
	TTL_list = insert(TTL_list, buffer);

	if(ntohs (ethernet->ether_type) == ETHERTYPE_IP){
		if(ip->ip_p==IPPROTO_TCP){
			strcpy(buffer, "TCP");
			transLayer = insert(transLayer, buffer);
			process_tcp(packet, size_ip);                 
		} else if(ip->ip_p == IPPROTO_UDP){
			strcpy(buffer, "UDP");
			transLayer = insert(transLayer, buffer);
			process_udp(packet, size_ip);                       
		} else if(ip->ip_p == IPPROTO_ICMP){
			strcpy(buffer, "ICMP");
			transLayer = insert(transLayer, buffer);
			process_icmp(packet, size_ip, ip);
		} else{
			sprintf(buffer, "0x%02x", ip->ip_p);  
			transLayer = insert(transLayer, buffer);
		}
	}     
}


Node* insert(Node *node, char* insert_value){
     Node *tmp = node;
     while(tmp!=NULL){
         if(!strcmp(tmp->value,insert_value)){
             tmp->number++;
             return node;
             }
         tmp=tmp->next;
         }  
     Node *newnode = (Node*) malloc (sizeof(Node));
     strcpy(newnode->value,insert_value);
     newnode->number = 1;
     newnode->next = node;
     return newnode;
}

Arp_node* insert_arp_node(Arp_node* node, char* mac, char* ip) {
	Arp_node *tmp = node;
	while (tmp!= NULL) {
		if (!strcmp(tmp->mac,mac)) {
			return node;
		}
		tmp = tmp->next;
	}
	Arp_node* newnode = (Arp_node*) malloc (sizeof(Arp_node));
	strcpy(newnode->mac, mac);
	strcpy(newnode->ip, ip);
	newnode->next = node;
	
	return newnode;
}


void print_arp(Arp_node* node) {
	printf("--- Unique ARP participants ---\n\n");
	if (node == NULL)
		printf("(no results)\n");
	while (node != NULL) {
		printf("%s / %s\n", node->mac ,node->ip);
		node=node->next;
	}
	printf("\n");
}

void print(char* category, Node *node, int total){
	float fraction;
	printf("--- %s ---\n\n", category);
	if(node==NULL)
		printf("(no results)\n");
	while (node!=NULL) {
		fraction = node->number;
		fraction /= total;
		fraction *= 100;
		printf("%17s %7d  %5.2f%%\n", node->value, node->number, fraction);
		node=node->next;              
	}
	printf("\n");
}


void print_summary(char* timebuffer, struct timeval start_time, char* timeDuration){
	printf("=== Summary ===\n\n");
	printf("  start date: %s%ld\n",timebuffer,start_time.tv_usec);
	printf("    Duration: %s\n",timeDuration);
	printf("   # Packets: %d\n",packets);
	printf("    Smallest: %d bytes\n",smallest_pkt);
	printf("     Largest: %d bytes\n",largest_pkt);
	printf("     Average: %.2f bytes\n\n",(float)total_bytes/packets);
}

void free_nodes(Node *node){
     struct link_node *tmp;
       while(node!= NULL){
           tmp=node;
           node=node->next; 
           free(tmp);
       }
     }

void free_arp_nodes(Arp_node *node) {
	Arp_node * tmp;
	while (node != NULL) {
		tmp = node;
		node = node->next;
		free(tmp);
	}
}

void  process_tcp(const u_char* packet, u_int size_ip){
      TCP_packets++;
      char buffer[MAX_BUF_SIZE];
      const struct tcphdr *tcp_header ; /* The TCP header */
      tcp_header  = (struct tcphdr*)(packet + ETHERNET_SIZE + size_ip);
      sprintf(buffer, "%d", htons (tcp_header->th_sport));  
      TCP_src_ports = insert(TCP_src_ports, buffer);  
      sprintf(buffer, "%d", htons (tcp_header->th_dport));  
      TCP_dest_ports = insert(TCP_dest_ports, buffer);  
      strcpy(buffer,"");
      if(tcp_header->ack)
        strcat(buffer, "ACK ");
      if(tcp_header->fin)
        strcat(buffer, "FIN ");
      if(tcp_header->psh)
        strcat(buffer, "PSH ");
      if(tcp_header->rst)
        strcat(buffer, "RST ");
      if(tcp_header->syn)
        strcat(buffer, "SYN ");
        
      TCP_flags = insert(TCP_flags, buffer); 
      int hlen = TH_OFF(tcp_header ) * 4;
      if(hlen > sizeof(*tcp_header ))
              process_tcp_option(hlen, tcp_header);
}
    
void  process_udp(const u_char* packet, u_int size_ip){
	UDP_packets++;
	char buffer[MAX_BUF_SIZE];
	const struct udphdr *udp_header; /* The TCP header */
	udp_header = (struct udphdr*)(packet + ETHERNET_SIZE + size_ip);
	sprintf(buffer, "%d", htons (udp_header->source));  
	UDP_src_ports = insert(UDP_src_ports, buffer);  
	sprintf(buffer, "%d", htons (udp_header->dest));  
	UDP_dest_ports = insert(UDP_dest_ports, buffer);                
}

void  process_icmp(const u_char* packet, u_int size_ip, const struct sniff_ip *ip){
	ICMP_packets++;
	char buffer[MAX_BUF_SIZE];
	char msg[MAX_BUF_SIZE*2];
	strcpy(msg, "");
	const struct icmphdr *icmp_header; 
	icmp_header = (struct icmphdr*)(packet + ETHERNET_SIZE + size_ip);
	sprintf(buffer, "%s", inet_ntoa(ip->ip_src)); 
	ICMP_src_IP = insert(ICMP_src_IP, buffer); 
	sprintf(buffer, "%s", inet_ntoa(ip->ip_dst)); 
	ICMP_dest_IP = insert(ICMP_dest_IP, buffer); 
	sprintf(buffer, "%d", icmp_header->type); 
	ICMP_TYPE = insert(ICMP_TYPE, buffer); 
	sprintf(buffer, "%d", icmp_header->code); 
	ICMP_CODE = insert(ICMP_CODE, buffer);      
	strcat(msg, get_icmp_response(icmp_header->type, icmp_header->code));  
	ICMP_RESPONSE = insert(ICMP_RESPONSE, msg);  
}
    
char* get_icmp_response(int type, int code){
      char* type_msg = (char*) malloc (20); 
      char code_msg[20];
      switch(type){
               case 0:
                    strcpy(type_msg,"ECHO ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REPLY");
                                 break;
                            }
                    break;
                    
               case 3:
                    strcpy(type_msg,"DEST_UNRECHEABLE ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"NET_UNRECHEABLE");
                                 break;
                            case 1:
                                 strcpy(code_msg,"HOST_UNRECHEABLE");
                                 break;
                            case 2:
                                 strcpy(code_msg,"PROTO_UNRECHEABLE");
                                 break;
                            case 3:
                                 strcpy(code_msg,"PORT_UNRECHEABLE");
                                 break;
                            case 4:
                                 strcpy(code_msg,"FRAG_REQUIRED");
                                 break;
                            case 5:
                                 strcpy(code_msg,"SRC_FAILED");
                                 break;
                            case 6:
                                 strcpy(code_msg,"NET_UNKNOWN");
                                 break;
                            case 7:
                                 strcpy(code_msg,"HOST_UNKNOWN");
                                 break;
                            case 8:
                                 strcpy(code_msg,"SRC_ISOLATED");
                                 break;
                            case 9:
                                 strcpy(code_msg,"NET_PROHIBITED");
                                 break;
                            case 10:
                                 strcpy(code_msg,"HOST_PROHIBITED");
                                 break;
                            case 11:
                                 strcpy(code_msg,"NET_TOS");
                                 break;
                            case 12:
                                 strcpy(code_msg,"HOST_TOS");
                                 break;
                            case 13:
                                 strcpy(code_msg,"COMMU_PROHIBITED");
                                 break;
                            case 14:
                                 strcpy(code_msg,"HOST_VIOLATION");
                                 break;
                            case 15:
                                 strcpy(code_msg,"CUTOFF");
                                 break;
                            }
                    break;
                    
               case 4:
                    strcpy(type_msg,"SRC_QUENCH ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"SRC_QUENCH");
                                 break;
                            }
                    break;
                
               case 5:
                    strcpy(type_msg,"REDIRECT_MSG ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"DATAGRAM_NET");
                                 break;
                            case 1:
                                 strcpy(code_msg,"DATAGRAM_HOST");
                                 break;
                            case 2:
                                 strcpy(code_msg,"DATAGRAM_TOS_NET");
                                 break;
                            case 3:
                                 strcpy(code_msg,"DATAGRAM_TOS_HOST");
                                 break;
                            }
                    break; 
                 
               case 8:
                    strcpy(type_msg,"ECHO ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REQUEST");
                                 break;
                            }
                    break; 
                      
               case 9:
                    strcpy(type_msg,"ROUTER ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"ADVERTISEMENT");
                                 break;
                            }
                    break; 
                    
               case 10:
                    strcpy(type_msg,"ROUTER_SOLI ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"DISCO/SELE/SOLI");
                                 break;
                            }
                    break; 
                    
               case 11:
                    strcpy(type_msg,"TIMXCEED ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"INTRANS");
                                 break;
                            case 1:
                                 strcpy(code_msg,"FRAGMENT");
                                 break;
                            }
                    break;
               
               case 12:
                    strcpy(type_msg,"PARA_PROB ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"POINTER_ERROR");
                                 break;
                            case 1:
                                 strcpy(code_msg,"MISS_OPTION");
                                 break;
                            case 2:
                                 strcpy(code_msg,"BAD_LENGTH");
                                 break;
                            }
                    break; 
                    
               case 13:
                    strcpy(type_msg,"TIMESTAMP ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"TIMESTAMP");
                                 break;
                            }
                    break;
               
               case 14:
                    strcpy(type_msg,"TIMESTAMP ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REPLY");
                                 break;
                            }
                    break;
               
               case 15:
                    strcpy(type_msg,"INFORMATION ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REQUEST");
                                 break;
                            }
                    break;
               
               case 16:
                    strcpy(type_msg,"INFORMATION ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REPLY");
                                 break;
                            }
                    break;
                    
               case 17:
                    strcpy(type_msg,"ADDRESS_MASK ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REQUEST");
                                 break;
                            }
                    break;
               
               case 18:
                    strcpy(type_msg,"ADDRESS_MASK ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"REPLY");
                                 break;
                            }
                    break;
               
               case 30:
                    strcpy(type_msg,"TRACEROUTE ");
                    switch(code){
                            case 0:
                                 strcpy(code_msg,"Info_Request");
                                 break;
                            }
                    break;
                    
               }
               
      strcat(type_msg, code_msg);
      return type_msg;
}

void process_tcp_option(int hlen, const struct tcphdr *tcp_header){
    char buffer[MAX_BUF_SIZE];
    uint8_t *tcp_options_pointer;
    tcp_options_pointer = (uint8_t *)tcp_header  + sizeof(*tcp_header );
    int option_length_left = hlen - sizeof(*tcp_header);
    int option_length, i;
    int EOL=0,NOP=0,MAXSEG=0,WINDOW=0,SACK=0, ECHO=0, ECHOREPLY=0,SACK_PERMITTED=0,TIMESTAMP=0;
    bool option_table[255];
    
    for (i=0; i<255; i++)
        option_table[i] = false;
    while (option_length_left>0){
          int current_option = *tcp_options_pointer;
          if(current_option == TCPOPT_NOP)
                   option_length = 1; 
          else{
                   tcp_options_pointer++;
                   uint8_t *temp_len = (uint8_t *)tcp_options_pointer;
                   tcp_options_pointer--;
                   option_length = (int)*temp_len;
              } 
         if(!option_table[current_option]){
              sprintf(buffer, "0x%02x", current_option); 
              TCP_options = insert(TCP_options, buffer); 
              option_table[current_option]=true;
              }  
          for (i=0; i<option_length; i++)
          (void)*tcp_options_pointer++;
          option_length_left = option_length_left - option_length;
          }
}  
