#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 1024

int splitWords(char*, char**, int);
void execute(char**);

int main(){
	char line[MAX_LENGTH];
	while(1){
		printf("$");
		fgets(line, MAX_LENGTH, stdin);
		char  *argv[MAX_LENGTH];
		//split line into word array;
		int count=splitWords(line, argv, 0);
		if(strcmp(argv[0],"exit") == 0)
			exit(1);
		else
			execute(argv); //execute argv
	}
	
	return 0;
}

int splitWords(char* line, char** argv, int count){
	char* tok;
	tok=strtok(line, " \n	");
	while(tok!= NULL){
		argv[count++]=tok;//malloc((strlen(tok)+1));
		tok=strtok(NULL, " ");		
	}
	return count;
}

void execute(char **argv){
	pid_t pid=fork();
	int status;
	if(pid<0){
		perror("error");
		exit(1);
	}
		
	else if(pid==0){
		execvp(*argv, argv);
	}
	else{
		waitpid(-1, &status, 0);
	}

}
