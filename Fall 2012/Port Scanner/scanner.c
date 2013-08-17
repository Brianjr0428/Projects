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

#include "scanner.h"
#include "portScanner.h"

int get_rand_port() {
	int port;
	srand((unsigned)time(NULL));
	port = rand() % 50000 + 1025;
	return port;
}

int port_scanner(char* ip_address1, unsigned short port1, int protocol1, int task_id, struct task_data *tasks, int *scan_technique) {
    struct sockaddr_in serverSocketAddr;
    int raw_socket, one=1, protocol = protocol1;
    const int *val=&one; 
    unsigned long int dest_IP = inet_addr(ip_address1);
    unsigned short int dest_port = port1;
    unsigned short int src_port= get_rand_port();
    int states_count[5] = {0,0,0,0,0};    
    //int scan_technique[6] = {1,1,1,1,1,1}; 

	serverSocketAddr.sin_family=AF_INET;
	serverSocketAddr.sin_port=dest_port;
	serverSocketAddr.sin_addr.s_addr=dest_IP;
    char * src_ip = GetLocalIp();
    unsigned long src_IP = inet_addr(src_ip);
    int i; 
	

	if (dest_port != 0) {
	    if(scan_technique[4]){
	    //printf("Begin TCP ACK scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		// printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		process_tcp_ack(serverSocketAddr, val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].ack_state = PORT_STATE_OPEN;}
		if(states_count[1]>0) 
			tasks[task_id].ack_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].ack_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].ack_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].ack_state = PORT_STATE_OPEN_FILTERED;
		}

	    if(scan_technique[0]){
	    //printf("Begin TCP SYN scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		//printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		process_tcp_syn(serverSocketAddr, val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].syn_state = PORT_STATE_OPEN; }
		if(states_count[1]>0)
			tasks[task_id].syn_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].syn_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].syn_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].syn_state = PORT_STATE_OPEN_FILTERED;
	    }  
	     
	    if(scan_technique[1]){
	    //printf("Begin TCP NULL scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		//printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		process_tcp_null(serverSocketAddr, val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].null_state = PORT_STATE_OPEN; }
		if(states_count[1]>0)
			tasks[task_id].null_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].null_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].null_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].null_state = PORT_STATE_OPEN_FILTERED;  
	    }     
	    if(scan_technique[2]){
	    //printf("Begin TCP FIN scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		//printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		process_tcp_fin(serverSocketAddr, val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].fin_state = PORT_STATE_OPEN; }
		if(states_count[1]>0)
			tasks[task_id].fin_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].fin_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].fin_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].fin_state = PORT_STATE_OPEN_FILTERED; 
	    }         
	    if(scan_technique[3]){
	    //printf("Begin TCP Xmas scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		//printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		process_tcp_Xmas(serverSocketAddr, val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].xmax_state = PORT_STATE_OPEN; }
		if(states_count[1]>0)
			tasks[task_id].xmax_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].xmax_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].xmax_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].xmax_state = PORT_STATE_OPEN_FILTERED;  
	    } 

	}

	if (protocol != 0) {
	    if(scan_technique[5]){
	    //printf("Begin Protocol scan:\n");
		serverSocketAddr.sin_addr.s_addr=dest_IP;
		//printf("Summary of ip %s:\n", inet_ntoa(serverSocketAddr.sin_addr));
		for (i=0;i<5;i++)
		states_count[i] = 0;
		if (protocol == IPPROTO_TCP)
		   fill_in_TCP_hdr(serverSocketAddr, protocol, val, src_IP, dest_IP, src_port, 80, states_count);
		else if (protocol == IPPROTO_UDP)
		     fill_in_UDP_hdr(serverSocketAddr, protocol, val, src_IP, dest_IP, src_port, dest_port, states_count);
		else if (protocol == IPPROTO_ICMP)
		     fill_in_ICMP_hdr(serverSocketAddr, protocol,val, src_IP, dest_IP, src_port, dest_port, states_count);
		else 
		     fill_in_PRO_hdr(serverSocketAddr, protocol,val, src_IP, dest_IP, src_port, dest_port, states_count);

		if(states_count[0]>0) {
			//printf("ok");
			tasks[task_id].protocol_state = PORT_STATE_OPEN; 			 
		}
		if(states_count[1]>0)
			tasks[task_id].protocol_state = PORT_STATE_CLOSED;
		if(states_count[2]>0)
			tasks[task_id].protocol_state = PORT_STATE_FILTERED;  
		if(states_count[3]>0)
			tasks[task_id].protocol_state = PORT_STATE_UNFILTERED;
	 	if(states_count[4]>0)
			tasks[task_id].protocol_state = PORT_STATE_OPEN_FILTERED;  
		}
	}

}

/*
int main(int argc, char * argv[]){

    struct sockaddr_in serverSocketAddr;
    port_scanner(char* ip_address1, unsigned short port1, int protocol1);
}
*/



void fill_in_TCP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 5;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;

   	struct pseudo_header pshdr;

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
     raw_socket=socket(AF_INET,SOCK_RAW,protocol);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons (src_port);
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpsyn(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; 
	tcpheader->urg_ptr = 0;

    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
    if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
		perror("setsockopt failed");
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             break;                                                 
         }
         else{
           send_iph=(struct iphdr *)datagram;
           rec_iph=(struct iphdr *)buffer;    
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = send_iph->daddr; 
           if(rec_iph->saddr == send_iph->daddr){
           if (rec_iph->protocol == IPPROTO_ICMP){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 3 || 
                  (unsigned int)(rec_icmph->code) == 9 || (unsigned int)(rec_icmph->code) == 10 || 
                  (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      states_count[2]++;
                      printf("states_count[2] %d\n", states_count[2]);
                      break;
                      } // end of if ((unsigned int)(rec_icmph->type) == 3)
                  else if((unsigned int)(rec_icmph->code) == 2){
                       port_state = 1; 
                       //printf("okay\n");
                       states_count[1]++;
                       //printf("states_count[1] %d\n", states_count[1]);
                       break;
                       }//end of else if((unsigned int)(rec_icmph->code) == 2)
               }//end of if ((unsigned int)(rec_icmph->type) == 3)
               else{
                    port_state = 0; 
                    states_count[0]++;
                    //printf ("Protocol %d is open. ", rec_iph->protocol);
                    //print_protocol_service(rec_iph->protocol);
                    //printf("\n");
                    break;
                    }//end of else
           }//end of if (rec_iph->protocol == IPPROTO_ICMP)
           else{
                port_state = 0; 
                states_count[0]++;
                //printf ("Protocol %d is open. ", rec_iph->protocol);
                //print_protocol_service(rec_iph->protocol);
                //printf("\n");
                break;
                }//end of else    
                }      
         }     
     }
     if (port_state == 5){
        port_state = 4;   
        states_count[4]++;
        //printf("states_count[4] %d\n", states_count[4]);
        }
      close(raw_socket);       
     }	


void fill_in_UDP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 5;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct udphdr *udpheader;
    struct iphdr *rec_iph, *send_iph;

    struct in_addr sin, din;

   	struct pseudo_header pshdr;

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
     raw_socket=socket(AF_INET,SOCK_RAW,protocol);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	
    ipheader = (struct iphdr *)datagram;
    udpheader=(struct udphdr  *) (datagram + sizeof(struct ip)); 
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_UDP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = 0;
    
    //UDP Header
    udpheader->source = htons(src_port);
    udpheader->dest = htons(dest_port);
    udpheader->len = htons(sizeof(struct udphdr));
	udpheader-> check = 0;

    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
    if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
		perror("setsockopt failed");
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             break;                                                 
         }
         else{
           send_iph=(struct iphdr *)datagram;
           rec_iph=(struct iphdr *)buffer;    
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = send_iph->daddr; 
           if(rec_iph->saddr == send_iph->daddr){
           if (rec_iph->protocol == IPPROTO_ICMP){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 3 || 
                  (unsigned int)(rec_icmph->code) == 9 || (unsigned int)(rec_icmph->code) == 10 || 
                  (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      states_count[2]++;
                      //printf("states_count[2] %d\n", states_count[2]);
                      break;
                      } // end of if ((unsigned int)(rec_icmph->type) == 3)
                  else if((unsigned int)(rec_icmph->code) == 2){
                       port_state = 1; 
                       //printf("okay\n");
                       states_count[1]++;
                       //printf("states_count[1] %d\n", states_count[1]);
                       break;
                       }//end of else if((unsigned int)(rec_icmph->code) == 2)
               }//end of if ((unsigned int)(rec_icmph->type) == 3)
               else{
                    port_state = 0; 
                    states_count[0]++;
                    //printf ("Protocol %d is open. ", rec_iph->protocol);
                    //print_protocol_service(rec_iph->protocol);
                    //printf("\n");
                    break;
                    }//end of else
           }//end of if (rec_iph->protocol == IPPROTO_ICMP)
           else{
                port_state = 0; 
                states_count[0]++;
                //printf ("Protocol %d is open. ", rec_iph->protocol);
                //print_protocol_service(rec_iph->protocol);
                //printf("\n");
                break;
                }//end of else    
                }      
         }     
     }
     if (port_state == 5){
        port_state = 4;   
        states_count[4]++;
        //printf("states_count[4] %d\n", states_count[4]);
        }
      close(raw_socket);       
     }	


void fill_in_ICMP_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 5;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct icmphdr *icmpheader;
    struct iphdr *rec_iph, *send_iph;

    struct in_addr sin, din;

   	struct pseudo_header pshdr;

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
     raw_socket=socket(AF_INET,SOCK_RAW,protocol);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	
    ipheader = (struct iphdr *)datagram;
    icmpheader=(struct icmphdr  *) (datagram + sizeof(struct ip)); 
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_ICMP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = 0;
    
    //ICMP Header
    icmpheader->type = ICMP_ECHO; 
    icmpheader->code = 0; 
    icmpheader->un.echo.id  = 0;
    icmpheader->checksum = 0; 
    icmpheader->un.echo.sequence  = 0; 
    icmpheader->checksum = cksum_icmp((unsigned short *)icmpheader, sizeof(struct icmphdr));

    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
    if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
		perror("setsockopt failed");
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             break;                                                 
         }
         else{
           send_iph=(struct iphdr *)datagram;
           rec_iph=(struct iphdr *)buffer;    
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = send_iph->daddr; 
           if(rec_iph->saddr == send_iph->daddr){
           if (rec_iph->protocol == IPPROTO_ICMP){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 3 || 
                  (unsigned int)(rec_icmph->code) == 9 || (unsigned int)(rec_icmph->code) == 10 || 
                  (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      states_count[2]++;
                      printf("states_count[2] %d\n", states_count[2]);
                      break;
                      } // end of if ((unsigned int)(rec_icmph->type) == 3)
                  else if((unsigned int)(rec_icmph->code) == 2){
                       port_state = 1; 
                       //printf("okay\n");
                       states_count[1]++;
                       //printf("states_count[1] %d\n", states_count[1]);
                       break;
                       }//end of else if((unsigned int)(rec_icmph->code) == 2)
               }//end of if ((unsigned int)(rec_icmph->type) == 3)
               else{
                    port_state = 0; 
                    states_count[0]++;
                    //printf ("Protocol %d is open. ", rec_iph->protocol);
                    //print_protocol_service(rec_iph->protocol);
                    //printf("\n");
                    break;
                    }//end of else
           }//end of if (rec_iph->protocol == IPPROTO_ICMP)
           else{
                port_state = 0; 
                states_count[0]++;
                //printf ("Protocol %d is open. ", rec_iph->protocol);
                //print_protocol_service(rec_iph->protocol);
                //printf("\n");
                break;
                }//end of else    
                }      
         }     
     }
     if (port_state == 5){
        port_state = 4;   
        states_count[4]++;
        //printf("states_count[4] %d\n", states_count[4]);
        }
      close(raw_socket);       
     }	

void fill_in_PRO_hdr(struct sockaddr_in serverSocketAddr,int protocol, const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 5;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;
    raw_socket=socket(AF_INET,SOCK_RAW,protocol);

    ipheader = (struct iphdr *)datagram;
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = protocol;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = 0;

     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
    

    if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
		perror("setsockopt failed");
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             break;                                                 
         }
         else{
           send_iph=(struct iphdr *)datagram;
           rec_iph=(struct iphdr *)buffer;   
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = send_iph->daddr; 
           if(rec_iph->saddr == send_iph->daddr){
           if (rec_iph->protocol == IPPROTO_ICMP){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 3 || 
                  (unsigned int)(rec_icmph->code) == 9 || (unsigned int)(rec_icmph->code) == 10 || 
                  (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      states_count[2]++;
                      printf("states_count[2] %d\n", states_count[2]);
                      break;
                      } // end of if ((unsigned int)(rec_icmph->type) == 3)
                  else if((unsigned int)(rec_icmph->code) == 2){
                       port_state = 1; 
                       //printf("okay\n");
                       states_count[1]++;
                       //printf("states_count[1] %d\n", states_count[1]);
                       break;
                       }//end of else if((unsigned int)(rec_icmph->code) == 2)
               }//end of if ((unsigned int)(rec_icmph->type) == 3)
               else{
                    port_state = 0; 
                    states_count[0]++;
                    //printf ("Protocol %d is open. ", rec_iph->protocol);
                    //print_protocol_service(rec_iph->protocol);
                    //printf("\n");
                    break;
                    }//end of else
           }//end of if (rec_iph->protocol == IPPROTO_ICMP)
           else{
                port_state = 0; 
                states_count[0]++;
                //printf ("Protocol %d is open. ", rec_iph->protocol);
                //print_protocol_service(rec_iph->protocol);
                //printf("\n");
                break;
                }//end of else    
                }      
         }     
     }
     if (port_state == 5){
        port_state = 4;   
        states_count[4]++;
        //printf("states_count[4] %d\n", states_count[4]);
        }
     close(raw_socket);
     }	

     
unsigned short cksum_icmp(unsigned short *address, int len)
{
    register int sum = 0;
    u_short answer = 0;
    register u_short *k = address;
    register int nleft = len;
    while (nleft > 1)
    {
      sum += *k++;
      nleft -= 2;
    }
    if (nleft == 1)
    {
      *(u_char *) (&answer) = *(u_char *) k;
      sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);   
    answer = ~sum;             
    return (answer);
}     

unsigned short checksum(unsigned short *ptr,int bytes) 
{
   register short result;
   register long sum=0;
   unsigned short odd_byte;

   while(bytes>1) {
 		sum+=*ptr++;
 		bytes-=2;
     }
   if(bytes==1) {
 		odd_byte=0;
 		*((u_char*)&odd_byte)=*(u_char*)ptr;
 		sum+=odd_byte;
        }
   sum = (sum>>16) + (sum & 0xffff);
   sum = sum + (sum>>16);
   result=(short)~sum;
   return(result);
      }


char* GetLocalIp()  
{        
    int MAXINTERFACES=16;  
    char *ip = NULL;  
    int fd, intrface, retn = 0;    
    struct ifreq buf[MAXINTERFACES];    
    struct ifconf ifc;    

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) >= 0)    
    {    
        ifc.ifc_len = sizeof(buf);    
        ifc.ifc_buf = (caddr_t)buf;    
        if (!ioctl(fd, SIOCGIFCONF, (char *)&ifc))    
        {    
            intrface = ifc.ifc_len / sizeof(struct ifreq);    

            while (intrface-- > 0)    
            {    
                if (!(ioctl (fd, SIOCGIFADDR, (char *) &buf[intrface])))    
                {    
                    ip=(inet_ntoa(((struct sockaddr_in*)(&buf[intrface].ifr_addr))->sin_addr));    
                    break;  
                }                        
            }  
        }    
        close (fd);    
        return ip;    
    }  
} 

void making_tcpsyn(struct tcphdr *tcphr){
     tcphr->fin=0;
     tcphr->syn=1;
     tcphr->rst=0;
     tcphr->psh=0;
     tcphr->ack=0;
     tcphr->urg=0;
     }

void making_tcpnull(struct tcphdr *tcphr){
     tcphr->fin=0;
     tcphr->syn=0;
     tcphr->rst=0;
     tcphr->psh=0;
     tcphr->ack=0;
     tcphr->urg=0;
     }
void making_tcpfin(struct tcphdr *tcphr){
     tcphr->fin=1;
     tcphr->syn=0;
     tcphr->rst=0;
     tcphr->psh=0;
     tcphr->ack=0;
     tcphr->urg=0;
     }
void making_tcpXmas(struct tcphdr *tcphr){
     tcphr->fin=1;
     tcphr->syn=0;
     tcphr->rst=0;
     tcphr->psh=1;
     tcphr->ack=0;
     tcphr->urg=1;
     }
void making_tcpack(struct tcphdr *tcphr){
     tcphr->fin=0;
     tcphr->syn=0;
     tcphr->rst=0;
     tcphr->psh=0;
     tcphr->ack=1;    
     }

void print_result(int *states_count){
     if(states_count[1]>0)
         printf("%d closed port(s).\n", states_count[1]);   
     if(states_count[2]>0)
         printf("%d filtered port(s).\n", states_count[2]);   
     if(states_count[3]>0)
         printf("%d unfiltered port(s).\n", states_count[3]);  
     if(states_count[4]>0)
         printf("%d open|filtered port(s).\n", states_count[4]);
     printf("\n");          
     }

void print_protocol_service(int protocol){
     switch(protocol){
            case 1: 
                 printf ("Service: ICMP");
                 break; 
            case 6: 
                 printf ("Service: TCP");
                 break;
            case 17: 
                 printf ("Service: UDP");
                 break;   
         }
     }
     
void print_service(int port){
     switch(port){
            case 21: 
                 printf ("Service: FTP");
                 break; 
            case 22: 
                 printf ("Service: SSH");
                 break;
            case 25: 
                 printf ("Service: SMTP");
                 break; 
            case 43: 
                 printf ("Service: WHOIS");
                 break;
            case 80: 
                 printf ("Service: HTTP");
                 break;
            case 110: 
                 printf ("Service: POP");
                 break;
            case 143: 
                 printf ("Service: IMAP\n");
                 break;
            case 587: 
                 printf ("Service: SMTP\n");
                 break;
  
         }
     }


void process_tcp_syn(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 5;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;

   	struct pseudo_header pshdr;

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
     raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons (src_port);
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpsyn(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; 
	tcpheader->urg_ptr = 0;

    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
    if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
    {
		perror("setsockopt failed");
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 2;
             states_count[2]++; 
             break;                                            
         }
         else {
           
           send_iph=(struct iphdr *)datagram;
           send_tcph=(struct tcphdr *)(datagram+sizeof(struct ip));
           rec_iph=(struct iphdr *)buffer;

           if (rec_iph->protocol == 1){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 2 ||             
                  (unsigned int)(rec_icmph->code) == 3 || (unsigned int)(rec_icmph->code) == 9
                   || (unsigned int)(rec_icmph->code) == 10 || (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      break;
                      } 
               }
           }

           rec_tcph=(struct tcphdr *)(buffer+sizeof(struct ip));
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = send_iph->daddr;
           if(rec_tcph->source == send_tcph-> dest && rec_iph->saddr == send_iph->daddr){
           
            if (rec_tcph->syn && rec_tcph->ack){
               port_state = 0;
               //printf ("Port %u of is open. ", ntohs((unsigned short int)rec_tcph->source));
               //print_service(ntohs((unsigned short int)rec_tcph->source));
               //printf("\n");
		states_count[0]++;
               break;
               }
            else if (rec_tcph->syn && !rec_tcph->ack){
                 port_state = 0;
                 //printf ("Port %u of is open. ", ntohs((unsigned short int)rec_tcph->source));
                 //print_service(ntohs((unsigned short int)rec_tcph->source));
                 //printf("\n");
		states_count[0]++;
                 break;
 
                 }
            else if (rec_tcph->rst){
                 port_state = 1;
                 states_count[1]++;
                 break;
                 }
            }
         }     
     }
     if (port_state == 5){
        port_state = 2;   
        states_count[2]++;
        }
        
     close(raw_socket);
     }	

void process_tcp_null(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 0;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;
   	struct pseudo_header pshdr;
   	
     raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
	

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
    
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons ( src_port );
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpnull(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; 
	tcpheader->urg_ptr = 0;
	
    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));

 	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }

	if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}

     int server_size = sizeof(serverSocketAddr);
     data_size=0;
     while(1){
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             //printf("okay\n");
             break;                                               
         }
         else {
              
           send_iph=(struct iphdr *)datagram;
           send_tcph=(struct tcphdr *)(datagram+sizeof(struct ip));
           rec_iph=(struct iphdr *)buffer;

           if (rec_iph->protocol == 1){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 2 ||             
                  (unsigned int)(rec_icmph->code) == 3 || (unsigned int)(rec_icmph->code) == 9
                   || (unsigned int)(rec_icmph->code) == 10 || (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      break;
                      } 
               }
           }

           rec_tcph=(struct tcphdr *)(buffer+sizeof(struct ip));
           
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = rec_iph->daddr;
           if(rec_tcph->source == send_tcph-> dest && rec_iph->saddr == send_iph->daddr){
            
            if (rec_tcph->rst){
                 port_state = 1;
                 states_count[1]++;
                 }
            break;
            }
         }     
     }
     if (port_state == 0){
        port_state = 4;
        states_count[4]++;  
        }
     close(raw_socket);
     }	

void process_tcp_fin(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 0;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;
   	struct pseudo_header pshdr;

     raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
    
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons ( src_port );
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpfin(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; 
	tcpheader->urg_ptr = 0;
	
    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;  
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
	if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0; 
     while(1){
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;                                  
             break;
         }
         else {
           send_iph=(struct iphdr *)datagram;
           send_tcph=(struct tcphdr *)(datagram+sizeof(struct ip));
           rec_iph=(struct iphdr *)buffer;

           if (rec_iph->protocol == 1){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 2 ||             
                  (unsigned int)(rec_icmph->code) == 3 || (unsigned int)(rec_icmph->code) == 9
                   || (unsigned int)(rec_icmph->code) == 10 || (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      break;
                      } 
               }
           }
           rec_tcph=(struct tcphdr *)(buffer+sizeof(struct ip));
           
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = rec_iph->daddr;
           if(rec_tcph->source == send_tcph-> dest && rec_iph->saddr == send_iph->daddr){
            
            if (rec_tcph->rst){
                 port_state = 1;
                 states_count[1]++;
                 break;
                 }
            break;
            }
         }     
     }
     if (port_state == 0){
        port_state = 4;
        states_count[4]++;   
        }  
        
     close(raw_socket);
     }	

void process_tcp_Xmas(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 0;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;

    struct in_addr sin, din;
   	struct pseudo_header pshdr;

     raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
    
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons ( src_port );
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpXmas(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; 
	tcpheader->urg_ptr = 0;
	
    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));

	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
	if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;  
     while(1){
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 4;
             states_count[4]++;
             break;                                                   
         }
         else {
              
           send_iph=(struct iphdr *)datagram;
           send_tcph=(struct tcphdr *)(datagram+sizeof(struct ip));
           rec_iph=(struct iphdr *)buffer;

           if (rec_iph->protocol == 1){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 2 ||             
                  (unsigned int)(rec_icmph->code) == 3 || (unsigned int)(rec_icmph->code) == 9
                   || (unsigned int)(rec_icmph->code) == 10 || (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      break;
                      } 
               }
           }

           rec_tcph=(struct tcphdr *)(buffer+sizeof(struct ip));
           
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = rec_iph->daddr;
           if(rec_tcph->source == send_tcph-> dest && rec_iph->saddr == send_iph->daddr){
            
            if (rec_tcph->rst){
                 port_state = 1;
                 states_count[1]++;
                 break;
                 }
            }
         }     
     }
     if (port_state == 0){
        port_state = 4;
        states_count[4]++;   
        }  
        
     close(raw_socket);
     }


void process_tcp_ack(struct sockaddr_in serverSocketAddr,const int *val, unsigned long src_IP, unsigned long int dest_IP, unsigned short int src_port, unsigned short int dest_port, int *states_count){
    int raw_socket, data_size, port_state = 0;
    char datagram[4096], buffer[4096];
    struct iphdr *ipheader;
    struct tcphdr *tcpheader;
    struct iphdr *rec_iph, *send_iph;
    struct tcphdr *rec_tcph, *send_tcph;
    struct icmphdr *icmph;
    

    struct in_addr sin, din;
   	struct pseudo_header pshdr;

     raw_socket=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
     if(raw_socket<0){
         printf("Fail to get root id to create raw socket!");
         exit(1);                                                    
     }   
    struct timeval timeout = {1,0};     
//	if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}

    memset(datagram, 0, 4096);
    memset(buffer, 0, 4096);
    
    ipheader = (struct iphdr *)datagram;
    tcpheader = (struct tcphdr *)(datagram+sizeof(struct ip));
    //Fill in the IP Header
    ipheader->ihl = 5;
    ipheader->version = 4;
    ipheader->tos = 0;
    ipheader->tot_len = sizeof (struct ip) + sizeof (struct tcphdr);
    ipheader->id = htons (54321);	
    ipheader->frag_off = htons(16384);
    ipheader->ttl = 64;
    ipheader->protocol = IPPROTO_TCP;
    ipheader->check = 0;		
    ipheader->saddr = src_IP;
    ipheader->daddr = dest_IP;
    ipheader->check = checksum ((unsigned short int *)datagram, ipheader->tot_len>>1);
    
    //TCP Header
	tcpheader->source = htons ( src_port );
	tcpheader->dest = htons (dest_port);
	tcpheader->seq = htonl(1105024978);
	tcpheader->ack_seq = 0;
	tcpheader->doff = sizeof(struct tcphdr) / 4;		
	making_tcpack(tcpheader);

	tcpheader->window = htons (5840);	
	tcpheader->check = 0; tcpheader->urg_ptr = 0;
	
    sin.s_addr=ipheader->saddr;
    din.s_addr=ipheader->daddr;
    pshdr.source_address = src_IP;
	pshdr.dest_address = dest_IP;
	pshdr.placeholder = 0;
	pshdr.protocol = IPPROTO_TCP;
	pshdr.tcp_length = htons( sizeof(struct tcphdr) );
	memcpy(&pshdr.tcp , tcpheader , sizeof (struct tcphdr));
	
	tcpheader->check = checksum( (unsigned short*) &pshdr , sizeof (struct pseudo_header));


	if((data_size=sendto(raw_socket,datagram, sizeof(struct iphdr) + sizeof(struct tcphdr),0,(struct sockaddr *) &serverSocketAddr, sizeof(serverSocketAddr)))<0){
        perror("sendto failed");                  
    }
	if (setsockopt (raw_socket, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout, sizeof(timeout)) < 0)
//	if (setsockopt (raw_socket, IPPROTO_IP, IP_HDRINCL, val, sizeof (int)) < 0)
	{
		printf ("Error setting IP_HDRINCL. Error number : %d . Error message : %s \n" , errno , strerror(errno));
		exit(1);
	}
     int server_size = sizeof(serverSocketAddr);
     data_size=0;
//     int i=5;     
     while(1){
         if((data_size=recvfrom(raw_socket,buffer,512,0,(struct sockaddr *)&serverSocketAddr,&server_size))<0){
             port_state = 2;  
             states_count[2]++; 
             break;                                              
         }
         else {
              
           send_iph=(struct iphdr *)datagram;
           send_tcph=(struct tcphdr *)(datagram+sizeof(struct ip));
           rec_iph=(struct iphdr *)buffer;

           if (rec_iph->protocol == 1){   
              struct icmphdr *rec_icmph = (struct icmphdr *)(buffer + sizeof(struct ip));
               if ((unsigned int)(rec_icmph->type) == 3){
                  if((unsigned int)(rec_icmph->code) == 1 || (unsigned int)(rec_icmph->code) == 2 ||             
                  (unsigned int)(rec_icmph->code) == 3 || (unsigned int)(rec_icmph->code) == 9
                   || (unsigned int)(rec_icmph->code) == 10 || (unsigned int)(rec_icmph->code) == 13){
                      port_state = 2; 
                      break;
                      } 
               }
           }

           rec_tcph=(struct tcphdr *)(buffer+sizeof(struct ip));
           
           memset(&sin, 0, sizeof(sin));
           sin.s_addr = rec_iph->saddr;
           memset(&din, 0, sizeof(din));
           din.s_addr = rec_iph->daddr;
           if(rec_tcph->source == send_tcph-> dest && rec_iph->saddr == send_iph->daddr){
           
            if (rec_tcph->rst){
                 port_state = 3;
                 states_count[3]++;
                 }
            break;
            }
//         i--;  
         }     
     }
     if (port_state == 0){
        port_state = 2;  
        states_count[2]++;
        }
         
     close(raw_socket);
     }	
