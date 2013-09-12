#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <fcntl.h>
#include <signal.h>
#include "head.h"

#define MAX_LENGTH 1024

void  parse(char*, char**);
void executeOneCommand(char*);
void execute(char**, int , bool);

int i;
bool back;
int pidf=0;
int pidb=0;

int main(){
	char line[MAX_LENGTH];
	while(1){
		signal (SIGCHLD, sig_fork);
		printf("myshell: ");
		if(fgets(line, MAX_LENGTH, stdin)==NULL)
			exit(1);

		if(!strcmp(line,"\n"))
			continue;
		line[strlen(line)-1]='\0';
		if(!strcmp(line,"exit"))
			exit(1);
		char *dirLine;
		if(isCd(line)){
			dirLine=trimSpace(line,dirLine);
			if(chdir(dirLine)<0){
				char msg[MAX_LENGTH];
				sprintf(msg, "-bash: cd: %s", dirLine);
				perror(msg);
			}
			continue;
		}
		int cmd=0;
		char *commands[MAX_LENGTH];
		char* tok;
		tok = strtok(line, ";");		
		while(tok != NULL){
			commands[cmd++]=tok;
			tok=strtok(NULL, ";");
		}
		for(i=0;i<cmd;i++)
			executeOneCommand(commands[i]);
	}	
	return 0;
}

void executeOneCommand(char *line){
		back=false;
		char *argv[MAX_LENGTH];
		//split line into word array;
		parse(line, argv);
		int index=0;
		int len=0;
		int i;
		while(argv[index++]!='\0')
			len++;
		int idNum[MAX_LENGTH];
		pid_t pid=fork();
		int status;
		if(pid<0){
			perror("error");
			exit(1);
		}
		else if(pid==0){
			int checkOut=outCheck(argv, len);
			if(checkOut==1||checkOut==2){
				int fd;
				if(checkOut==1)
					fd= open(argv[len-1], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
				else if(checkOut==2)
					fd= open(argv[len-1], O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR) ;
				if(fd == -1){
					perror("open");
					return exit(1);
				}
				dup2(fd, STDOUT_FILENO);
				dup2(fd, STDERR_FILENO);	
				close(fd);
				char  *argv2[MAX_LENGTH];
				
				for(i=0;i<len-2;i++)
					argv2[i]=argv[i];
				execute(argv2,len-2,pipeCheck(argv2,len-2)); //execute argv
			}
			else
				execute(argv, len, pipeCheck(argv,len)); //execute argv
		}
		else{
			if(back){
				idNum[pidf]=(int)pid;
				printf("[%d] %d\n",pidf+1, idNum[pidf]);
				pidf++;
				if(pidf>1){
					printf("[%d]	Done\n",++pidb);
				}
					
			}
			else{
				while(wait(&status)>0);
				if(pidb<pidf){
					printf("[%d]+	Done\n",++pidb);
					pidf=0;
					pidb=0;
				}	
				usleep(100000);
			}
		}	
}

void execute(char **argv, int len, bool hasPipe){
	if(!hasPipe){
		if(inputCheck(argv,len)){
			inputReplace(argv,len);
			execute(argv, len+1, pipeCheck(argv,len+1));
		}
		else{
			if(execvp(*argv, argv)<0){
				printf("-bash: %s: command not found\n", argv[0]);
				exit(1);
			}
		}
	}		
	else{
		char *front[MAX_LENGTH];
		char *end[MAX_LENGTH];
		int i;
		int index=0;
		int index1=0;
		int index2=0;
		bool meetPipe=false;
		int pIndex=findLastPipe(argv,len);
		while(index<len){
			if(index<pIndex){
				front[index1++]=argv[index];
			}
			else if (index > pIndex){
				end[index2++]=argv[index];
			}
			index++;
		}
		int fd[2];
		pipe(fd);
		int pid=fork();
		int status;
		if(pid<0){
			perror("fork");
			exit(1);
		}
		else if(pid==0){
			dup2(fd[0],0);
			close(fd[1]);
			if(execvp(*end, end)<0){
				printf("-bash: %s: command not found\n", end[0]);
				exit(1);
			}
		}
		else{
			dup2(fd[1],1);
			close(fd[0]);
			execute(front, index1, pipeCheck(front,index1));			
			while(wait(&status)>0);
		}
	}
}

void  parse(char *line, char **argv)
{
	while (*line != '\0') {
		while (*line == ' ' || *line == '\t' || *line == '\'' || *line == '\"'|| *line == '&'|| *line == '\n'){
			if(*line == '&')
				back=true;
			*line++ = '\0';
		}
		if(*line == '\0')
			break;
		if(!back){
			*argv++= line;     
			while (*line != '\0' && *line != ' ' && *line != '\t' && *line != '\n'&& *line != '\''&& *line != '\"') 
				line++;             		}
	}
     *argv = '\0';                
}
