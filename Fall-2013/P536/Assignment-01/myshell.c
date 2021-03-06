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
int initParse(char*, bool*, char**);
void executeOneCommand(char*, bool);
void execute(char*, bool);

int i;
bool back;
int pidf=0;
int pidb=0;

int main(){
	
	char line[MAX_LENGTH];
	while(1){
		back=false;
		signal (SIGCHLD, sig_fork);
		printf("myshell: ");
		if(fgets(line, MAX_LENGTH, stdin)==NULL)
			exit(1);
		if(!strcmp(line,"\n"))
			continue;
		line[strlen(line)-1]='\0';
		if(!checkSyntax(line)){
			if(pidb<pidf){
				printf("[%d]+	Done\n",++pidb);
				pidf=0;
				pidb=0;
			}
			exit(1);	
		}
		if(!strcmp(line,"exit"))
			exit(1);
		bool stats[MAX_LENGTH];
		for(i=0;i<MAX_LENGTH;i++)
			stats[i]=false;
		char *commands[MAX_LENGTH];
		int cmd=initParse(line,stats,commands);
		
		for(i=0;i<cmd;i++)
			executeOneCommand(commands[i], stats[i]);	
	}	
	return 0;
}

void executeOneCommand(char *line, bool stat){
		while(*line==' ')
			*line++;
		if(isCd(line)){
			char *dirLine;
			dirLine=trimSpace(line,dirLine);
			if(strlen(dirLine)==0)
				dirLine=getenv("HOME");
			if(chdir(dirLine)<0){
				char msg[MAX_LENGTH];
				sprintf(msg, "-bash: cd: %s", dirLine);
				perror(msg);
			}
			if(!back&&pidb<pidf){
					printf("[%d]+	Done\n",++pidb);
					pidf=0;
					pidb=0;
				}	
		}
		else{
			back=stat;
			//split line into word array;
			int idNum[MAX_LENGTH];
			pid_t pid=fork();
			int status;
			if(pid<0){
				perror("error");
				exit(1);
			}
			else if(pid==0){
				int checkOut=outCheck(line);
				if(checkOut==1||checkOut==2){
					char *lines[MAX_LENGTH];
					parseOutput(line,lines);
					lines[1]=trimWord(lines[1]);
					int fd;
					if(checkOut==1){
						fd= open(lines[1], O_RDWR | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR) ;
					}else if(checkOut==2){
						fd= open(lines[1], O_RDWR | O_CREAT | O_APPEND, S_IRUSR | S_IWUSR);	
					}
										
					if(fd == -1){
						perror("open");
						return exit(1);
					}
					dup2(fd, STDOUT_FILENO);
					dup2(fd, STDERR_FILENO);	
					close(fd);
					execute(lines[0],pipeCheck(lines[1])); //execute argv
				}
				else
					execute(line,pipeCheck(line)); //execute argv
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

}

void execute(char *line, bool hasPipe){
	
	if(!hasPipe){
		char  *argv[MAX_LENGTH];
		if(inputCheck(line)){
			char *lines[MAX_LENGTH];
			parseInput(line, lines);
			lines[1]=trimWord(lines[1]);
			int fd ;
			if((fd= open(lines[1], O_RDONLY, S_IRUSR)) == -1){
				char msg[MAX_LENGTH];
				sprintf(msg, "-bash: %s", lines[1]);
				perror(msg);
				return exit(1);
			}
			dup2(fd, STDIN_FILENO);
			dup2(fd, STDERR_FILENO);	
			close(fd);
			parse(lines[0], argv);
			if(execvp(*argv, argv)<0){
				printf("-bash: %s: command not found\n", argv[0]);
				exit(1);
			}
		}
		else{
			parse(line, argv);
			if(execvp(*argv, argv)<0){
				printf("-bash: %s: command not found\n", argv[0]);
				exit(1);
			}
		}
	}		
	else{
		char *lines[MAX_LENGTH];
		parsePipe(line, lines);
		int fd[2];
		pipe(fd);
		int pid=fork();
		int status;
		if(pid<0){
			perror("fork");
			exit(1);
		}
		else if(pid==0){
			char *exlines[MAX_LENGTH];
			parse(lines[1], exlines);
			dup2(fd[0],0);
			close(fd[1]);
			if(execvp(*exlines, exlines)<0){
				printf("-bash: %s: command not found\n", exlines[0]);
				exit(1);
			}
		}
		else{
			dup2(fd[1],1);
			close(fd[0]);
			execute(lines[0], pipeCheck(lines[0]));			
			while(wait(&status)>0);
		}
	}

}

int initParse(char *line, bool *stats, char **argv)
{
	int count=0;
	bool tempStat=false;
	while (*line != '\0') {
		while (*line == '&' || *line == ';' || *line == '\n'){
			if(*line == '&')
				tempStat=true;
			else 
				tempStat=false;
			if(count>0)	
					stats[count-1]=tempStat;
			*line++ = '\0';
		}
		if(*line == '\0')
			break;
		*argv++= line;  
		
		count++;  
		while (*line != '\0' && *line != ';'&& *line != '&'&& *line != '\t' && *line != '\n') 
			line++;
	}
     *argv = '\0';    
	return count;            
}
