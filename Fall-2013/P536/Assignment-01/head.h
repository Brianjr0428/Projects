int findLastPipe(char **argv, int len){
	int index=0;
	int i;
	for(i=0;i<len;i++){
		if(!strcmp(argv[i], "|"))
			index=i;
	}
	return index;
}

void  parse(char *line, char **argv)
{
	while (*line != '\0') {
		while (*line == ' ' || *line == '\t' || *line == '\'' || *line == '\"'||  *line == '\n'){
			*line++ = '\0';
		}	
		if(*line == '\0')
			break;
		*argv++= line;     
		while (*line != '\0' && *line != ' ' && *line != '\t' && *line != '\n'&& *line != '\''&& *line != '\"' ) 
			line++;             
	}
     *argv = '\0';                
}

void parseInput(char* line, char** lines){
	*lines++= line;
	while(*line!='<'){
		*line++;
	}
	*line++='\0';
	*lines=line;
	
}

void parseOutput(char* line, char** lines){
	*lines++= line;
	while(*line!='>'){
		*line++;
	}
	while(*line=='>')
		*line++='\0';
	*lines=line;
	
}

void parsePipe(char* line, char** lines){
	char *tmp;
	tmp=line;
	int count=0;
	while(*tmp!='\0'){
		if(*tmp=='|')
			count++;
		tmp++;
	}
	*lines++=line;
	while(*line!='\0'){
		if(*line=='|'){
			count--;
			if(count==0)
				break;
		}
		*line++;
	}
	*line++='\0';
	*lines=line;
}

bool inputCheck(char *line){
	while(*line!='\0'){
		if(*line=='<')
			return true;
		*line++;
	}
	return false;
}

int outCheck(char *line){
	while(*line!='\0'){
		if(*line=='>'){
			if(*(line+1)!='>'){
				return 1;
			} else {
				return 2;
			}
		}
		*line++;
	}
	return 0;
}

bool pipeCheck(char *line){
	while(*line!='\0'){
		if(*line=='|')
			return true;
		*line++;
	}
	return false;
}

bool checkSyntax(char* line){
	bool stat=false;
	while(*line!='\0'){
		if(*line != ' ' && *line != '\t' &&  *line != '\n'&&  *line != '&'&&  *line != ';')
			stat=true;
		if(*line == '&' || *line == ';'){
			if(!stat){
				printf("-bash: syntax error near unexpected token `%c'\n",*line);
				return false;
			}
				
			stat=false;
		}
		*line++;
	}
	return true;
}


bool isCd(char* line){
	if(line[0]=='c'&&line[1]=='d')
		return (line[2]==' '||line[2]=='\0');
	return false;
}

char*  trimWord(char* word){
	char *newLine;
	while(*word==' '){
		*word++;
	}
	newLine=word;
	while(*word!= ' ' && *word!= '\t' &&  *word!= '\n'&&*word!='\0')
		*word++;
	*word='\0';
	return newLine;
}

char* trimSpace(char* original, char *toTrim){
	int len = strlen(original);
	int index=3;
	while(original[index]==' ')
		index++;
	int start=index;
	index=len-1;
	while(original[index]==' ')
		index--;
	int end=index;
	index=0;
	int i;
	char *newLine;
	index=0;
	for(i=start;i<=end;i++)
		newLine[index++]=original[i];
	newLine[index]='\0';
	
	return newLine;
}


void handler(int sig)
{
    printf("Signal trapped: %d\n", sig);
    exit(0);
    return;
}

void sig_fork(int signo)
{
	pid_t pid;
	int stat;
	pid=waitpid(0,&stat,WNOHANG);
	return;
}


bool backCheck(char **argv,int  len){
	int i;
	for(i=0;i<len;i++){
		if(!strcmp(argv[i], "&"))
			return true;
	}
	return false;
}



