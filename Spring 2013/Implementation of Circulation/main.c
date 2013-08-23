#include <stdio.h>
#include <stdlib.h>

typedef struct Node{
    int name;
    int demand;
    int capacity;
    int lowerbound;
    struct Node* next;
}Node;//end struct node


typedef struct Adjlist{
    int name;
    int demand;
    int capacity;
    int lowerbound;
    Node *head;
}Adjlist;//end adjlist struct


Node* newNode_create(int name, int demand, int capacity, int lowerbound);
Node* newNode_create(int name, int demand, int capacity, int lowerbound){
    Node* newnode = (Node*)malloc(sizeof(Node));
    newnode->next = NULL;
    newnode->name=name;
    newnode->demand=demand;
    newnode->capacity=capacity;
    newnode->lowerbound=lowerbound;
    return newnode;
}//end newNode_create


int main(void){
    
    int vertex;
    printf("Please enter how many vertices in your graph:\n");
    scanf("%d",&vertex);
    printf("You have %d vertices\n", vertex);
    
    Adjlist* array=(Adjlist*)malloc(vertex*sizeof(Adjlist));
    int i;
    int num_neighbor, name, demand, capacity, lowerbound;
    Node* currentptr;

    for(i=0;i<vertex;i++){
        printf("Please enter demand of vertex%d\n",i);
        scanf("%d", &demand);
        array[i].name=i;
        array[i].demand=demand;
        array[i].capacity=-1;
        array[i].lowerbound=-1;
        array[i].head=NULL;
        //if(array[i].head==NULL) printf("%d null\n",i);
        //else printf("%d not null\n",i);
    }//end for
    
    for(i=0;i<vertex;i++){
        printf("Please enter the number of neighbors of vertex %d\n", i);
        scanf("%d",&num_neighbor);
        currentptr = array[i].head;
        
        while(num_neighbor > 0){
            printf("Please enter following information about the neighbor of vertext%d\n", i);
            printf("Enter name, demand, lowerbound, capacity in order and separeated by one space\n");
            
            scanf("%d %d %d %d", &name, &demand, &lowerbound, &capacity);
            printf("name:%d, demand:%d, lowerbound:%d, capacity:%d\n", name, demand, lowerbound, capacity);
            
            if(array[i].head==NULL){
                Node* newnode=newNode_create(name, demand, capacity, lowerbound);
                array[i].head=newnode;
                currentptr=newnode;
            }//end if arrayhead=null
            else{
            
                //printf("before newnode\n");
                Node* newnode=newNode_create(name, demand, capacity, lowerbound);
                //printf("before ptr->next\n");
                currentptr->next = newnode;
                //printf("before curptr\n");
                currentptr=newnode;
                //printf("after curptr\n");
            }//end else=>arrayhead isn't null
                   
            num_neighbor--;
        }//end while num_neighbor !=0
        currentptr=array[i].head;
        while(currentptr!=NULL){
            printf("i:%d,name:%d,demand:%d,lowerbound:%d,capacity:%d\n",i,currentptr->name,currentptr->demand,currentptr->lowerbound,currentptr->capacity);
            currentptr=currentptr->next;
        }
        
    }//end for //create the adjacent list for graph:done
    
    



    return 0;
}//end main
