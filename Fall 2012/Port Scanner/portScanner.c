/*
 * File:          portScanner.c
 * Description:   Project 2: A Basic Port Scanner
 */

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <math.h>

#include <sys/socket.h>
#include <errno.h> 
#include <pthread.h>
#include <netdb.h>	
#include <arpa/inet.h>
#include <netinet/tcp.h>	
#include <netinet/ip.h>	
#include <netinet/ip_icmp.h>
#include <sys/ioctl.h>
#include <net/if.h>

#include "scanner.h"
#include "portScanner.h"

#define random(x) (rand()%x)
#define MAX_NUM_LINES 1000
#define OK 0
#define ERROR -1
#define TRUE 1
#define FALSE 0
#define SYN_INDEX 0 
#define NULL_INDEX 1 
#define FIN_INDEX 2 
#define XMAS_INDEX 3
#define ACK_INDEX 4
#define PROTOCAL_INDEX 5
#define MAX_PROTOCOL_SIZE 255
#define RECV_BUF_SIZE 1024
#define SEND_BUF_SIZE 100
#define TIME_OUT 5

int port_num = 0;
unsigned short *port_list;
int ip_num = 0;
char ** ip_list;
int threads_num = 1;
int tasks_num   = 0;
int task_index  = 0;
pthread_mutex_t mutex_task_index;
int scan_technique[6] = {TRUE, TRUE, TRUE, TRUE, TRUE, TRUE};
int protocol_list[MAX_PROTOCOL_SIZE];
int protocal_num = 0;

struct task_data *tasks;

void *task_thread();
int get_unassigned_task(struct task_data *current_task);
int process_arguments (int argc, char **argv);
int read_file(char* file_name, char file_ip_list[MAX_NUM_LINES][MAX_IP_ADDRESS_LENGTH]);
void print_usage();

/* scan funtions */


int main(int argc, char **argv) {
	int rc;
	long t;
	int i, j, k, h;
	pthread_attr_t attr;
	void *status;
	
	/* process arguments */
	if (process_arguments(argc, argv) == ERROR) {
		printf("Input '-h' or '--help' to check the usage.\n");
		free(ip_list);
		free(port_list);
		exit(ERROR);
	}

	
	pthread_t threads[threads_num];
	
	/* assign memory to tasks */
	tasks = (struct task_data *)malloc(sizeof(struct task_data)*tasks_num);

	/* initialize tasks */
	for (i = 0; i < tasks_num;  i++) {
		j = i%(port_num + protocal_num);
		if (j < port_num) {
			tasks[i].port = port_list[j];
			tasks[i].protocol = 0;
		} else {
			h = j - port_num;
			tasks[i].port = 0;
			tasks[i].protocol = protocol_list[h];
		}		
		k = i/(port_num + protocal_num);
		strcpy(tasks[i].ip_address, ip_list[k]);	
		tasks[i].syn_state = PORT_STATE_UNKNOWN;
		tasks[i].null_state = PORT_STATE_UNKNOWN;
		tasks[i].fin_state = PORT_STATE_UNKNOWN;
		tasks[i].xmax_state = PORT_STATE_UNKNOWN;
		tasks[i].ack_state = PORT_STATE_UNKNOWN;
		tasks[i].protocol_state = PORT_STATE_UNKNOWN;
	}

	free(ip_list);
	free(port_list);

	
	//for (i = 0; i < tasks_num;  i++) {
	//	printf("task: %d - %s - %d\n", tasks[i].port, tasks[i].ip_address, tasks[i].protocol);
	//}

	//exit(0);

	printf("Starting port scanner...\n");
	
	pthread_mutex_init(&mutex_task_index, NULL);

	/* initialize and set thread detached attribute */
	pthread_attr_init(&attr);
	pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);

	for (t = 0; t < threads_num; t++) {
		// printf("In main: creating thread %ld\n", t);
		rc = pthread_create(&threads[t], &attr, task_thread, NULL);
		if (rc){
			printf("ERROR; return code from pthread_create() is %d\n", rc);
			exit(ERROR);
		}
		else
		{
			//printf("created thread number: %d", t);
		}

	}

	pthread_attr_destroy(&attr);

	/* Wait on the other threads */
	for (i = 0; i < threads_num; i++) {
		pthread_join(threads[i], &status);
	}
	printf("-----------------------------------------------------------------------------------------------\n");
	printf("        ip       | port | sevice | syn_state | null_state | fin_state | xmax_state| ack_state  \n", tasks[i].port, tasks[i].ip_address);
	for (i = 0; i < tasks_num; i++) {
		if (//tasks[i].ack_state == PORT_STATE_OPEN ||
			tasks[i].syn_state == PORT_STATE_OPEN) {
			//tasks[i].null_state == PORT_STATE_OPEN ||
			//tasks[i].fin_state == PORT_STATE_OPEN ||
			//tasks[i].xmax_state == PORT_STATE_OPEN)
			printf("%15s  %5d  ", tasks[i].ip_address, tasks[i].port);
			print_port_service(tasks[i].port);
			print_port_state(tasks[i].syn_state);
			printf("-");
			print_port_state(tasks[i].null_state);
			printf("-");
			print_port_state(tasks[i].fin_state);
			printf("-");
			print_port_state(tasks[i].xmax_state);
			printf("-");
			print_port_state(tasks[i].ack_state);
			printf("\n");
			if (verify_services(tasks[i].port, tasks[i].ip_address) == ERROR)
				printf("Verifying services failed\n");
		}

	}

	printf("-----------------------------------------------------------------------------------------------\n");
	for (i = 0; i < tasks_num; i++) {
		if (tasks[i].protocol_state == PORT_STATE_OPEN) {
			printf("Host: %s Protocol: [%d]-", tasks[i].ip_address, tasks[i].protocol);
			if (tasks[i].protocol == IPPROTO_TCP) {
				printf("TCP");
			} else if (tasks[i].protocol == IPPROTO_UDP) {
				printf("UDP");
			} else if (tasks[i].protocol == IPPROTO_ICMP) {
				printf("ICMP");
			} else {
				printf("Unknown");
			}
			printf("  Open\n");
		}
	}	


	// Free tasks
	free(tasks);
	pthread_mutex_destroy(&mutex_task_index);
	pthread_exit(NULL);
	
}

void *task_thread() {
	struct task_data my_task;
	int task_id;	

	while(TRUE) {

		if ((task_id = get_unassigned_task(&my_task)) == ERROR) {
			break;
		}

		port_scanner(my_task.ip_address, my_task.port, my_task.protocol, task_id, tasks, scan_technique);

		printf("task: port[%d] - ip[%s] - protocol[%d] done\n", my_task.port, my_task.ip_address, my_task.protocol);
	}

	pthread_exit((void*) OK);
}
/*
int my_port_scanner(char* ip_address, unsigned short port) {
	port_scanner(ip_address, port, 1);
}
*/

int get_unassigned_task(struct task_data *current_task) {
	int index_num;

	/* get current task index */
	pthread_mutex_lock(&mutex_task_index);
	if (task_index >= tasks_num) {
		pthread_mutex_unlock(&mutex_task_index);
		return ERROR;
	}
	index_num = task_index;
	task_index++;
	pthread_mutex_unlock(&mutex_task_index);

	/* set current task data */
	current_task->port = tasks[index_num].port;
	strcpy(current_task->ip_address, tasks[index_num].ip_address);
	current_task->protocol = tasks[index_num].protocol;

	return index_num;
}

int process_arguments (int argc, char **argv) {
	int c = 0; /* option character */
	int option = 0;
	int index, speedup, length, arg_len, i, j;
	char *token = NULL;
	int  port, port_down, port_up;
	char *outer_ptr = NULL;
	char *inner_ptr = NULL;
	char *port_down_str, *port_up_str;
	char *option_arg;
	char ip_address[MAX_IP_ADDRESS_LENGTH];
	char file_ip_list[MAX_NUM_LINES][MAX_IP_ADDRESS_LENGTH];
	int file_ip_num = 0;
	unsigned long int ip_prefix;
	int ip_prefix_len;
	struct sockaddr_in ip_prefix_addr;
	int ip_prefix_num = 0;
	char ip_prefix_list[MAX_NUM_LINES][MAX_IP_ADDRESS_LENGTH];
	int proto_down, proto_up;
	int protocal;

	memset(ip_address, '\0', sizeof(ip_address));

	struct option longopts[] = {
		{"help", no_argument, 0, 'h'},
		{"ports", required_argument, 0, 'p'},
		{"ip", required_argument, 0, 'i'},
		{"prefix", required_argument, 0, 'x'},
		{"file", required_argument, 0, 'f'},
		{"speedup", required_argument, 0, 'u'},
		{"scan", required_argument, 0, 's'},
		{"protocal-range", required_argument, 0, 'r'},
		{0, 0, 0, 0}
	};

	while (TRUE) {
		c = getopt_long (argc, argv, "hp:i:x:f:u:s:r:", longopts, &option);
		
		if (c == -1 || c == EOF)
			break;

		//printf("%s\n", optarg);
		switch (c) {
			case 'h':
				print_usage();
			case 'p':
				arg_len = strlen(optarg);
				option_arg = (char *)malloc(sizeof(char)*arg_len+1);
				strcpy(option_arg, optarg);
				token = strtok_r(optarg, ",", &outer_ptr);
				while (token != NULL) {
					length = strlen(token);
					if (token[0] == '[' && token[length-1] == ']') {
						token[length-1] = '\0';
						port_down_str = strtok_r(&token[1], "-", &inner_ptr);
						port_up_str = strtok_r(NULL, "-", &inner_ptr);
						if (port_down_str == NULL || port_up_str == NULL) {
							printf("Incorrect port range '%s'.\n", option_arg);
							free(option_arg);
							return ERROR;
						}
						port_down = atoi(port_down_str);
						port_up = atoi(port_up_str);
						if (strtok_r(NULL, ",", &inner_ptr) != NULL
							|| port_down < 1 || port_up < 1 || port_down > 65535
							|| port_up > 65535 || port_down >= port_up) {
							printf("Incorrect port range '%s'.\n", option_arg);
							free(option_arg);
							return ERROR;
						}
						port_num += port_up - port_down + 1;
						
					} else {
						port = atoi(token);
						if (port < 1 || port > 65535) {
							printf("Incorrect port '%s'.\n", token);
							free(option_arg);
							return ERROR;
						}
						port_num++;
					}		

					token = strtok_r(NULL, ",", &outer_ptr);
				}

				// printf("total port number:%d\n", port_num);
				port_list = (unsigned short *)malloc(sizeof(unsigned short)*port_num);
				
				// printf("%s\n", option_arg);	
				token = strtok_r(option_arg, ",", &outer_ptr);
				i = 0;
				while (token != NULL) {
					length = strlen(token);
					if (token[0] == '[' && token[length-1] == ']') {
						token[length-1] = '\0';
						port_down = atoi(strtok_r(&token[1], "-", &inner_ptr));
						port_up = atoi(strtok_r(NULL, "-", &inner_ptr));
						index = port_up - port_down + 1;
						for (j = 0;j < index; i++, j++) 
							port_list[i] = port_down + j;
					} else {
						port = atoi(token);
						port_list[i] = port;
						i++;
					}		

					token = strtok_r(NULL, ",", &outer_ptr);
				}
				free(option_arg);

				//for (i = 0; i < port_num; i++) {
				//	printf("port: %d\n",port_list[i]);
				//}
				break;
			case 'i':
				strcpy(ip_address, optarg);
				break;
			case 'x':
				token = strtok(optarg, "/");
				ip_prefix = inet_addr(token);
				if ( ip_prefix == ERROR) {
					printf("Incorrect ip prefix\n");
					return ERROR;
				}

				token = strtok(NULL, "/");
				if (token == NULL) {
					printf("Incorrect ip prefix\n");
					return ERROR;
				}
				ip_prefix_len = atoi(token);
				if (ip_prefix_len == 0) {
					printf("Incorrect ip prefix\n");
					return ERROR;
				}
				printf("%d\n", ip_prefix_len);
				ip_prefix_len = 32 - ip_prefix_len;			
				
				ip_prefix_num = pow(2, ip_prefix_len);
				for (i = 0; i < ip_prefix_num; i++) {
					ip_prefix_addr.sin_addr.s_addr = ip_prefix;
					strcpy(ip_prefix_list[i], inet_ntoa(ip_prefix_addr.sin_addr));
					ip_prefix = ntohl(ip_prefix);
					ip_prefix++;
					ip_prefix = htonl(ip_prefix);	
				}
	
				break;
			case 'f':
				if ((file_ip_num = read_file(optarg, file_ip_list)) == ERROR) {
					printf("Can't open file '%s'\n", optarg);
					return ERROR;
				}
				
				//i = 0;
				//while (TRUE) {
				//	if (strlen(file_ip_list[i]) != 0) {
				//		printf("ip: %s\n",file_ip_list[i]);
				//		i++;
				//	} else {
				//		break;
				//	}
				//}

				break;
			case 'u':
				speedup = atoi(optarg);
				// printf("%d\n",speedup);
				if (speedup < 1) {				
					printf("Incorrect speedup option argument '%s'.\n", optarg);
					return ERROR;
				} else 
				{
					threads_num = speedup;
					//printf("num threads: %d", threads_num);
				}
				break;
			case 's':
				/* SYN, NULL, FIN, XMAS, ACK */
				/* reset scan techniques*/
				scan_technique[SYN_INDEX] = FALSE;
				scan_technique[NULL_INDEX] = FALSE;
				scan_technique[FIN_INDEX] = FALSE;
				scan_technique[XMAS_INDEX] = FALSE;
				scan_technique[ACK_INDEX] = FALSE;
				scan_technique[PROTOCAL_INDEX] = FALSE;
				
				token = strtok(optarg, ",");
				while (token != NULL) {
					// printf( "arg is \"%s\"\n", token);
					if (strcmp(token, "SYN") == 0) 
						scan_technique[SYN_INDEX] = TRUE;
					else if (strcmp(token, "NULL") == 0)
						scan_technique[NULL_INDEX] = TRUE;
					else if (strcmp(token, "FIN") == 0)
						scan_technique[FIN_INDEX] = TRUE;
					else if (strcmp(token, "XMAS") == 0)
						scan_technique[XMAS_INDEX] = TRUE;				
					else if (strcmp(token, "ACK") == 0)
						scan_technique[ACK_INDEX] = TRUE;
					else if (strcmp(token, "Protocol") == 0)
						scan_technique[PROTOCAL_INDEX] = TRUE;
					else {
						printf("Incorrect scan option argument '%s'.\n", token);
						return ERROR;
					}

					token = strtok(NULL, ",");
				}
				break;
			case 'r':
				token = strtok_r(optarg, ",", &outer_ptr);
				while (token != NULL) {
					length = strlen(token);
					if (token[0] == '[' && token[length-1] == ']') {
						token[length-1] = '\0';
						port_down_str = strtok_r(&token[1], "-", &inner_ptr);
						port_up_str = strtok_r(NULL, "-", &inner_ptr);
						if (port_down_str == NULL || port_up_str == NULL) {
							printf("Incorrect protocal range.\n");
							return ERROR;
						}
						proto_down = atoi(port_down_str);
						proto_up = atoi(port_up_str);
						if (strtok_r(NULL, ",", &inner_ptr) != NULL
							|| proto_down < 1 || proto_up < 1 || proto_down > 255
							|| proto_up > 255 || proto_down >= proto_up) {
							printf("Incorrect protocal range.\n");
							return ERROR;
						}
						i = protocal_num;
						protocal_num += proto_up - proto_down + 1;
						for (j = 0;i < protocal_num; i++, j++) {
							protocol_list[i] = proto_down + j;
						}						
					} else {
						protocal = atoi(token);
						if (protocal < 1 || protocal > 255) {
							printf("Incorrect protocal number '%s'.\n", token);
							return ERROR;
						}
						protocol_list[protocal_num] = protocal;
						protocal_num++;
					}		

					token = strtok_r(NULL, ",", &outer_ptr);
				}


				//for (i = 0; i < protocal_num; i++)
				//	printf("protocol: %i\n", protocol_list[i]);
				break;
			case '?':
				print_usage();
		}
	}

	index = optind;
	if (index < argc) {
		for (; index < argc; index++)
			printf ("Non-option argument: %s\n", argv[index]);
		print_usage();
	}

	if (strlen(ip_address) > 1)
		ip_num ++;

	ip_num += file_ip_num;
	ip_num += ip_prefix_num;

	if (ip_num == 0) {
		printf("ip/prefix/file are required!\n");
		return ERROR;
	}

	if (port_num == 0) {
		port_num = 1024;
		port_list = (unsigned short *)malloc(sizeof(unsigned short)*port_num);
		for (j = 0; j < port_num; j++) {
			port_list[j] = j+1;
		}
	}

	ip_list = malloc(sizeof(char *)*ip_num);
	for (i = 0; i < ip_num; i++) {
		ip_list[i] = malloc(sizeof(char *)*MAX_IP_ADDRESS_LENGTH);	
	}

	i = 0;
	if (strlen(ip_address) > 1) {
		strcpy(ip_list[i], ip_address);
		i++;
	}

	if (file_ip_num > 0) {
		for (j = 0; j < file_ip_num; j++, i++) {
			strcpy(ip_list[i], file_ip_list[j]);
		}
	}

	if (ip_prefix_num > 0) {
		for (j = 0; j < ip_prefix_num; j++, i++) 
			strcpy(ip_list[i], ip_prefix_list[j]);
	}

	if (scan_technique[PROTOCAL_INDEX] == TRUE && protocal_num == 0) {
		protocal_num = 255;
		for (j = 0; j < protocal_num; j++) 
			protocol_list[j] = j;
	}


	tasks_num = ip_num * (port_num + protocal_num);
	
	//for (j = 0; j < ip_num; j++) {
	//	printf("ip: %s\n",ip_list[j]);
	//}

	return OK;
}

int read_file(char* file_name, char file_ip_list[MAX_NUM_LINES][MAX_IP_ADDRESS_LENGTH]) {
	FILE *file;
	char ip_address[MAX_IP_ADDRESS_LENGTH];
	int i = 0;
	int length;

	memset(file_ip_list, '\0', sizeof(file_ip_list));

	// Open the file
	if ((file = fopen(file_name, "r")) == NULL) 
		return ERROR;

	// Read the file
	while (fgets(ip_address, MAX_IP_ADDRESS_LENGTH, file) != NULL) {
		length = strlen(ip_address);
		if ( length < 2) {
		} else {
			ip_address[length-1] = '\0';
			strcpy(file_ip_list[i], ip_address);
			i++;
		}
	}

	// Close the file
	fclose ( file );

	return i;
}

void print_usage() {
	printf("Usage:\n");
	printf(" %s\n", "-h, --help");
	printf(" %s\n", "-p, --ports=<ports to scan>  ([1-1024] by default)");
	printf(" %s\n", "-i, --ip=<IP address to scan>");
	printf(" %s\n", "-x, --prefix=<IP prefix to scan>");
	printf(" %s\n", "-f, --file=<file name containing IP addresses to scan>");
	printf(" %s\n", "-u, --speedup=<parallel threads to use>");
	printf(" %s\n", "-s, --scan=<one or more scans> (SYN,NULL,FIN,XMAS,ACK,Protocol)");
	printf(" %s\n", "-r, --protocol-range=<transport layer protocols to scan> ([1-255] by default)");
	exit(OK);
}

int print_port_service(int port) {
	/*
	int i;
	for (i = 0; i < 21; i++) {
		if (port_service_list[i].port == port) {
			printf("%7s  ", port_service_list[i].service_name);
			return 0;
		}
	}
	printf("Unknown");
	return 0;
	*/
	struct servent *appl_name;
	appl_name = getservbyport(htons(port),"tcp");

	if (!appl_name)
	{
		printf(" Unknown ");
	}
	else
	{
		printf("%7s  ",appl_name->s_name);
	} 
}

int print_port_state(enum port_state state) {
	if (state == PORT_STATE_OPEN) 
		printf(" Open ");
	else if (state == PORT_STATE_CLOSED) 
		printf(" Closed ");
	else if (state == PORT_STATE_FILTERED) 
		printf(" Filtered ");
	else if (state == PORT_STATE_UNFILTERED) 
		printf(" Unfiltered ");
	else if (state == PORT_STATE_OPEN_FILTERED) 
		printf(" (Open|Filtered) ");
	else if (state == PORT_STATE_UNKNOWN) 
		printf(" Unknown ");
}

int verify_services(int port, char* ip_address) {
	char msg[SEND_BUF_SIZE];	
	
	switch(port){
		case 22: 
			if (verify_connection(port, ip_address, "", "", 0) == ERROR) {	
				return ERROR;
			};
			break;
		case 25: 
			if (verify_connection(port, ip_address, "", "220 ", 4) == ERROR) {	
				return ERROR;
			};
			break;
		case 587: 
			if (verify_connection(port, ip_address, "", "220 ", 4) == ERROR) {	
				return ERROR;
			};
			break; 
		case 43: 
			if (verify_connection(port, ip_address, "whois", "", 0) == ERROR) {	
				return ERROR;
			};
			break;
		case 80: 
			if (verify_connection(port, ip_address, "GET", "Server:", 0) == ERROR) {	
				return ERROR;
			};		
			break;
		case 110: 
			if (verify_connection(port, ip_address, "", "+OK", 4) == ERROR) {	
				return ERROR;
			};
			break;
		case 143: 
			if (verify_connection(port, ip_address, "", "]", 2) == ERROR) {	
				return ERROR;
			};
			break;

	}
	
	return OK;
}

int verify_connection(int port, char* ip_address, char *send_msg, char *msg_name, int l) {
	int serv_fd;
	struct sockaddr_in serv_addr;
	char recv_buf[RECV_BUF_SIZE];
	char msg[SEND_BUF_SIZE];
	int size, i;
	char *serv_infor;	

	// Time-out 
	struct timeval timeout;      
	timeout.tv_sec = TIME_OUT;
	timeout.tv_usec = 0;

	printf ("   -- ");
	
	memset(&serv_addr, 0, sizeof(serv_addr));
	serv_addr.sin_family = AF_INET;               // Internet address family
	serv_addr.sin_addr.s_addr = inet_addr(ip_address);  //Server IP address
	serv_addr.sin_port = htons(port);               // server port
	
	if ((serv_fd = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
		//perror("socket()");
		return ERROR;
	}

	// Set automatic time-out
	if (setsockopt (serv_fd, SOL_SOCKET, SO_RCVTIMEO, (char *)&timeout,
 			sizeof(timeout)) < 0) {
		//perror("setsockopt()");
		return ERROR;
	}

	if ( connect(serv_fd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0 ) {
		//perror("connect() failed");
		return ERROR;
	}
	
	sprintf(msg, "%s\r\n", send_msg);
	size = strlen(msg);
	if (size > 3) {
		send(serv_fd, msg, size, 0);
		//printf("- %s\n", msg);
	}
	
	if (recv(serv_fd, recv_buf, RECV_BUF_SIZE, 0) == ERROR) {
		return ERROR;
	}
	//printf("- %s\n", recv_buf);
	serv_infor = strstr(recv_buf, msg_name);
	if (serv_infor == NULL) 
		return ERROR;
	for (i = 0; i < RECV_BUF_SIZE; i++) {
		if (serv_infor[i] == '\n' )
			serv_infor[i] = '\0';
	}
	printf("%s\n", &serv_infor[l]);
	close(serv_fd);
}

