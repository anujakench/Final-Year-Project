						/* Program for Master */

/* Header files */
#include<stdio.h>
#include<stdlib.h>
#include<pcap.h>
#include<netinet/in.h>
#include<arpa/inet.h>
#include<netinet/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include<string.h>
#include<sys/types.h>
#include<sys/time.h>
#include<signal.h>

#define TIMEOUT_SECS 10

struct timespec t,t1;
struct timeval t2,t3;
unsigned char* packet;
pcap_t *descr;
int len;
struct ethhdr *eth;


/* Function handlet for SIGALRM */
void CatchAlarm(int signum)     
{
    
	printf("\n\t\tTIMEOUT :-(\n");
	pcap_breakloop(descr);
    	pcap_close(descr);
}
/* end of function */


void ether_head()
{
	 /* Source address (Master) */	
	eth->h_source[0]=0x00;
	eth->h_source[1]=0x1F;
	eth->h_source[2]=0xD0;
	eth->h_source[3]=0x3F;
	eth->h_source[4]=0x28;
	eth->h_source[5]=0x52;
	
	eth->h_proto=0x00;
	memcpy(packet,eth,len);	
}	
/* end of function */

void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
	char str[100],*p,*q,str1[100],s_dest[200];
	int id;
	int len1=6,j=0;
	const u_char *p1=packet ;
	p = (char *)malloc(100);
	q = (char *)malloc(100);
	p1+=6;
		
	strcpy(str,packet+14);
	p = strtok(str," ");
		
	if(strcmp(p,"INIT")!=0)
	{
		q = strtok(NULL,"\0");
   		strcpy(str1,q);
	}
	if(strcmp(p,"SYN")==0)
	{
		strcpy(q,str1);     
		q=strtok(q,".");    
		strcpy(str1,q);     
		id=atoi(str1);
		if(id ==2)
	        { 
		t.tv_sec = pkthdr->ts.tv_sec; 
		t.tv_nsec = pkthdr->ts.tv_usec; 
	 	}		
	}

	else if(strcmp(p,"REP") == 0)
	{
		strcpy(q,str1);     
		q=strtok(q,".");    
		strcpy(str1,q);     
 		id=atoi(str1);
	}
	else if(strcmp(p,"INIT")==0)
	{
		printf("\n\t\tReceived INIT packet....\n");
		while(len1--)
		{
			eth->h_dest[j]=*p1;
			p1++,j++;		
			
		}
		
	}
		
	else
 	printf("\n\t\tother packet\n\n");
        
}
/* end of function */



/* main function */
int main()
{
	char *dev;
	char erbuf[PCAP_ERRBUF_SIZE];
	struct timeval tim;
	struct pcap_pkthdr hdr;
	char *point;
	char str1[50];
	int i=0,j=0,counter=0;
	char ptr[200];
	pcap_t *descr1;
	/* For setting signal handler */	
	struct sigaction myAction;       
	struct itimerval timer;
	eth=(struct ethhdr *)malloc(sizeof(struct ethhdr));
	len=sizeof(struct ethhdr);
	strcpy(str1,"\0");
	packet=(char*)malloc(1514);
	point=(char *)malloc(100);

	dev=pcap_lookupdev(erbuf);
	if(dev==NULL)
	{
		printf("\n\t\terrbuf : %s\n\n",erbuf);
		exit(1);
	}
	
	descr=pcap_open_live(dev,BUFSIZ,0,-1,erbuf);
	if(descr==NULL)
	{
		printf("\n\t\tCannot open:%s\n",erbuf);
		exit(1);
	}

	do
	{
		printf("\n\t\tWaiting for INIT packet from client : %d \n",counter+1);
		i=pcap_loop(descr,1,my_callback,NULL);// wait for INIT packet
		ether_head();
        	strcpy(str1,"\0");
		strcpy(str1,"SYN 1.");
		memcpy(packet+14,str1,sizeof(str1));

		printf("\n\t\tSending SYNC packet to client : %d\n",counter+1);
		counter++;
		/* Send sync packet containing T1 */		
		i=pcap_sendpacket(descr,packet,1514);  
		if(i==-1)
		{	
			pcap_perror(descr,ptr);
			printf("\n\t\tERROR : %s\n",ptr);
			printf("\n\t\tError in inject function!!!\n");
		}
		
		memset(&myAction,0,sizeof(struct sigaction));
		myAction.sa_handler = CatchAlarm;

		/* block everything in handler */
    		if (sigfillset(&myAction.sa_mask) < 0) 
        		printf("sigfillset() failed");
    		myAction.sa_flags = 0;

    		if (sigaction(SIGALRM, &myAction, 0) < 0)
        		printf("sigaction() failed for SIGALRM");

		alarm(TIMEOUT_SECS);
		pcap_setdirection(descr,PCAP_D_IN);

		/* Wait for packet containig loop for T3 */
		i=pcap_loop(descr,1,my_callback,NULL); 
		if(i==-1)
			printf("\n\n\t\tError in pcap_loop\n");
		else if(i==-2)
		{
			strcpy(str1,"\0");
			strcpy(str1,"ERROR ");       //new
			descr1=pcap_open_live(dev,BUFSIZ,0,-1,erbuf);		
			if(descr1==NULL)
			{
				printf("\n\t\tCannot open:%s\n",erbuf);
				exit(1);
			}
			memcpy(packet+14,str1,sizeof(str1));
			i=pcap_sendpacket(descr1,packet,1514);  /* Sending error packet */
			if(i==-1)
				pcap_perror(descr1,point);
			printf("\n\t\tT3 not received... exiting\n");
			continue;
			pcap_close(descr1);
			
				
		}
		else
		{
			alarm(0);
			printf("\n\t\tDelay request packet received in time\n");
		}

		ether_head();	
	
		//T4 time sent
		strcpy(str1,"\0");
		strcpy(str1,"SYN 3.");
		memcpy(packet+14,str1,sizeof(str1));
		sprintf(str1,"%ld.%ld",t.tv_sec,t.tv_nsec);
		memcpy(packet+20,str1,sizeof(str1));

		i=pcap_sendpacket(descr,packet,1514);  //sending T4
		if(i==-1)
			printf("\n\n\t\tError in sending Delay response packet\n");

		/* Set signal handler for alarm signal */
    		myAction.sa_handler = CatchAlarm;
    		if (sigfillset(&myAction.sa_mask) < 0) /* block everything in handler */
        		printf("sigfillset() failed");
    		myAction.sa_flags = 0;

    		if (sigaction(SIGALRM, &myAction, 0) < 0)
        		printf("sigaction() failed for SIGALRM");
	
	
		alarm(TIMEOUT_SECS);
		pcap_setdirection(descr,PCAP_D_IN);
  		i=pcap_loop(descr,1,my_callback,NULL);   //T4 reply
	
	
		if(i==-1)
				printf("\n\t\tError in pcap_loop()\n");
		else if(i==-2)
		{
			
			strcpy(str1,"\0");
			strcpy(str1,"ERROR ");          //new
			memcpy(packet+14,str1,sizeof(str1));
		
			i=pcap_sendpacket(descr,packet,1514);  //sending error
			printf("\n\t\tT4 reply not received... exiting\n\n");
			continue;

			
		} 
		else
		{
			alarm(0);
			printf("\n\t\tT4 reply received in time\n");
			printf("\n\t\tClient %d : Request satisfied!!!\n\n\n\n\n",counter);
         	}

	}while(1);

         return 0;
}
