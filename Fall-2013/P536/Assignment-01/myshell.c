#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define MAX_LENGTH 1024

int splitWords(char*, char**, int);

int main(){
	char line[MAX_LENGTH];
	while(1){
		printf("$");
		fgets(line, MAX_LENGTH, stdin);
		char  *argv[MAX_LENGTH];
		//split line into word array;
		int count=splitWords(line, argv, 0);
		
		//test the word array, should be delated later;
		int i;
		for(i=0;i<count;i++){
			if(i==count-1)
				printf("%s",argv[i]);
			else
				printf("%s\n",argv[i]);
		}
			
		//system(line);
	}
	
	return 0;
}

int splitWords(char* line, char** argv, int count){
	char* tok;
	tok=strtok(line, " ");
	while(tok!= NULL){
		argv[count++]=tok;//malloc((strlen(tok)+1));
		tok=strtok(NULL, " ");		
	}
	return count;
}
