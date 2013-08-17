#include<stdio.h> 
#include<string.h> 
#include<stdlib.h> 
#include<sys/socket.h>
#include<errno.h> 
#include<pthread.h>
#include<netdb.h>	
#include<arpa/inet.h>
#include<netinet/tcp.h>	
#include<netinet/ip.h>	
#include<netinet/ip_icmp.h>
#include<netinet/udp.h>
#include<sys/ioctl.h>
#include<net/if.h>

struct pseudo_header {       

	unsigned int source_address;
	unsigned int dest_address;
	unsigned char placeholder;
	unsigned char protocol;
	unsigned short tcp_length;
	
	struct tcphdr tcp;
};

char* GetLocalIp();
void making_tcpsyn(struct tcphdr *tcphr);
void making_tcpnull(struct tcphdr *tcphr);
void making_tcpfin(struct tcphdr *tcphr);
void making_tcpXmas(struct tcphdr *tcphr);
void making_tcpack(struct tcphdr *tcphr);
void print_result(int *states_count);
void print_service(int port);
void print_protocol_service(int protocol);
void process_tcp_syn(struct sockaddr_in serverSocketAddr, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void process_tcp_null(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void process_tcp_fin(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void process_tcp_Xmas(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void process_tcp_ack(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void fill_in_TCP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void fill_in_UDP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void fill_in_ICMP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
void fill_in_PRO_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count);
unsigned short checksum(unsigned short *ptr,int bytes);
unsigned short cksum_icmp(unsigned short *address, int len);


