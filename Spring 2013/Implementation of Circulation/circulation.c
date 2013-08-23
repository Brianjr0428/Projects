#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>

#define MAX 999
#define ADDED true // maek a node as added if it has been added to a path
#define UNADDED false


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
    // to allocate memory for the new node.
    Node* newnode = (Node*)malloc(sizeof(Node));
    //assign values to the new node
    newnode->next = NULL;
    newnode->name=name;
    newnode->demand=demand;
    newnode->capacity=capacity;
    newnode->lowerbound=lowerbound;
    return newnode;
}//end newNode_create

int i,j,path_length,top=-1, bn=MAX, maxflow=0;
int capacity_list[MAX][MAX]; //a matrix to store capacity 
int flow[MAX][MAX];//a matrix to store flow 
bool status[MAX];

Node* currentptr;
Node* currentptr_source;
Node* currentptr_sink;

int find_min(int x, int y){
    return x<y? x:y;}

//print path node from source to sink
void print_path(int path[], int start, int target){
     i=0;
     printf("Find a path: ");
     while (path[i]!=target){
           if (path[i]==start){
              printf("Source -> ");
              i++;
              }
           else
               printf("%d -> ",path[i++]);
           
           }
     
     printf("Sink\n");   
     path_length=i;
     }

//set all status to "UNADDED"
void clear_status(bool status[]){
     for (i=0;i<MAX;i++)
     status[i]=UNADDED;
     }
    
//use DFS to find a s-t path
bool DFS(int path[], int start, int target, int path_index){
     int next_start=0;
     int current_nei=0;
     //set start as ADDED
     status[start]=ADDED;
     //set path_index as start
     path[path_index]=start;
     if (start==target)//if reach the sink node, we find a path
        return true;    
     while (current_nei<target+1){
           //call DFS recursively
           if (!status[current_nei]&&flow[start][current_nei]>0){
              //set current adjacent node as new start node                                             
              next_start=current_nei;
              if (DFS(path,next_start,target,++path_index))
                 return true; 
              else {
                   //check next adjacent node
                   path_index--;
                   }
                 }//end if   
           current_nei++;
     }//end while

     return false;
}    

//Ford-Fulkerson Algorithm
void max_flow(int path[],int start, int target){  
    printf("\nBegin to calculate maxflow:\n\n", maxflow);
     while (DFS(path, start, target, 0)){
           bn=MAX;
           // if there is a path, print it
           print_path(path, start, target);  
           //set all nodes as "UNADDED"    
           clear_status(status);
           //check all node in the path to find bottleneck
           for (i=0;i<path_length;i++){    
               bn=find_min(bn,flow[path[i]][path[i+1]]);
               } 
           //calculate maxflow
           maxflow+=bn;
           
           //update flow in residual graph
           for (i=0;i<path_length;i++){
               flow[path[i]][path[i+1]]-=bn;//if flow[i][j]is a forward edge, decrease by bn
               flow[path[i+1]][path[i]]+=bn;//if flow[i][j]is a backward edge, decrease by bn
               }    
           printf("Bottleneck of this path: %d\n\n", bn);
           }
           printf("maxflow of this circulation is: %d\n", maxflow);

     }
    
int main(void){
    int stack[MAX];
    int vertex;
    int sum_demand=0;
    int sum_positiveDemand=0;
    int path[MAX];
    
    //let users enter the number of vertices
    printf("Please enter how many vertices in your graph:\n");
    scanf("%d",&vertex);
    printf("You have %d vertices\n", vertex);
    
    Adjlist* array=(Adjlist*)malloc((vertex+2)*sizeof(Adjlist));//included source(index: vertex) and sink node(index:vertex +1)

    int num_neighbor, name, demand, capacity, lowerbound;
    for(i=0;i<vertex+2;i++){// let user enter the demand of every node
        if(i<vertex){//exclude the source and sink node
            printf("Please enter demand of vertex%d\n",i);
            scanf("%d", &demand);
            array[i].name=i;
            array[i].demand=demand;
            array[i].capacity=-1;
            array[i].lowerbound=-1;
            array[i].head=NULL;
        }//end if i< vertex
        else array[i].head=NULL;// set source and sink node
    }//end for
    
    for(i=0;i<vertex;i++){// start creating the linked list per node
        printf("Please enter the number of neighbors of vertex %d\n", i);
        scanf("%d",&num_neighbor);
        currentptr = array[i].head;
        
        while(num_neighbor > 0){ 
            printf("Please enter following information about the neighbor of vertext%d\n", i);
            printf("Enter name, demand, lowerbound, capacity in order and separeated by one space\n");
            
            scanf("%d %d %d %d", &name, &demand, &lowerbound, &capacity);
            printf("name:%d, demand:%d, lowerbound:%d, capacity:%d\n", name, demand, lowerbound, capacity);
            
            if(array[i].head==NULL){ //if there is no node now
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

    }//end for //create the adjacent list for graph:done
    
    //start eliminate lower bound by scanning every edge
    for(i=0;i<vertex;i++){
        currentptr = array[i].head;
        
        while(currentptr != NULL){
            if(currentptr->lowerbound > 0){//reset new capacity & demand
                //set new capacity
                currentptr->capacity=currentptr->capacity - currentptr->lowerbound;
                //subtracts- new demand on nodes which edges point to
                array[currentptr->name].demand=array[currentptr->name].demand - currentptr->lowerbound;
                currentptr->demand=currentptr->demand - currentptr->lowerbound;
                //add- new demand on nodes which has edge point out
                array[i].demand=array[i].demand + currentptr->lowerbound;              
            }//end if lowerbound > 0
        
            currentptr=currentptr->next;
        }//end while num_neighbor !=0
    }//end for //create the adjacent list for graph:done
    
    for(i=0;i<vertex;i++){//get the sum of demand of every node, and the sum of positive demands
        sum_demand = sum_demand + array[i].demand;
        if(array[i].demand>0) sum_positiveDemand = sum_positiveDemand + array[i].demand;
    }
    
    if(sum_demand!=0){
        printf("Circulation for this graph is not feasible because sum of demand is not zero\n");
        return 0;
    }//end of sum demand not 0
    
    else{//add source and sink nodes and edges
        
        for(i=0;i<vertex;i++){
            if(array[i].demand < 0){//create edge from s to the node
                
                if(array[vertex].head ==NULL){
                    Node* newnode=newNode_create(array[i].name, array[i].demand, 0-array[i].demand, 0);
                    array[vertex].head=newnode;
                    currentptr_source=newnode;
                }//end if source head=null
                else{
                    Node* newnode=newNode_create(array[i].name, array[i].demand, 0-array[i].demand, 0);
                    currentptr_source->next=newnode;
                    currentptr_source = newnode;
                }//end else sourcehead not null
                
            }//end if demand<0
            else if (array[i].demand >0){// create edge from node to sink
                currentptr=array[i].head;
                Node* newnode=newNode_create(vertex+1, 0, array[i].demand, 0);
                newnode->next=currentptr;
                array[i].head = newnode;
                
            }//end else if demand>0
        }//end for
        //print graph information
        printf("Sum of positive demand:%d\n",sum_positiveDemand);
        for(i=0;i<vertex+2;i++){
            printf("%d: demand=%d\n",i,array[i].demand);
            currentptr=array[i].head;
            while(currentptr!=NULL){
                printf("i:%d,name:%d,demand:%d,lowerbound:%d,capacity:%d\n",i,currentptr->name,currentptr->demand,currentptr->lowerbound,currentptr->capacity);
                currentptr=currentptr->next;
            }//end while
            
        }//end for 
   
        
    }//end
    
    // initilize the residual graph(named flow) and capacity matrix from adjacent list before
    for (i=0;i<vertex+2;i++){
        currentptr=array[i].head;
        while (currentptr!=NULL){
              capacity_list[i][currentptr->name]=currentptr->capacity;
              flow[i][currentptr->name]=currentptr->capacity;
              currentptr=currentptr->next;
              }
        }
       //compute the maxflow 
       max_flow(path,vertex, vertex+1);
       //if the graph is feasible, show the new flow in the graph
       if (sum_positiveDemand==maxflow){
          printf("Positive demand value is equal to maxflow, this graph is feasible.\nThe new flow is as following:\n");
          for(i=0;i<vertex+2;i++){
            currentptr=array[i].head;//update adjacent nodes of current node
            while (currentptr!=NULL){
                  if (i==vertex)
                     printf("Source node to node%d: %d\n",currentptr->name, flow[currentptr->name][i]);
                  else
                      printf("Node %d to node%d: %d\n",i, currentptr->name, flow[currentptr->name][i]);
                currentptr=currentptr->next;//update next adjacent node
            }//end while
            
        }//end for 
          }          
       else
           printf("Positive demand value is not equal to maxflow, this graph is not feasible.\n");
       
    return 0;
}//end main


