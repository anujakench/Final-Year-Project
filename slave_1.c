							/* Program for Slave:1 */


/* Header files */
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include<string.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include<linux/if.h>
#include<math.h>
#include<sys/time.h>
#include<linux/sockios.h>
#include<signal.h>


#define TIMEOUT_SECS 10

struct timespec t1,t2,t4;  //structures for storing nano-second timestamp
extern struct timespec t3;
struct timespec delay;
struct timespec offset;

pcap_t* descr;  //packet descriptor


/* Function handler for SIGALRM */
void CatchAlarm(int signum)     
{	
	printf("\n\tTIMEOUT :-(\n");
	pcap_breakloop(descr);
    	pcap_close(descr);
}
/* end of function */


/* Function for the addition of times(seconds and nanoseconds) */
void add_timespec(struct timespec *a,struct timespec *b,struct timespec *res)
{
	res->tv_nsec= a->tv_nsec + b->tv_nsec;
	res->tv_sec= a->tv_sec + b->tv_sec;
	
	if(res->tv_nsec>999999999)
	{
		res->tv_nsec-=1000000000;
		res->tv_sec++;	

	}

}
/* end of function */



/* Function for the subtraction of times(seconds and nanoseconds) */
void sub_timespec(struct timespec *a,struct timespec *b,struct timespec *res)
{
	res->tv_nsec= a->tv_nsec - b->tv_nsec;
	res->tv_sec= a->tv_sec - b->tv_sec;
	
	if(res->tv_nsec<0)
	{
		res->tv_nsec+=1000000000;
		res->tv_sec--;	

	}

}
/* end of function */



/* Function for the division of times(seconds and nanoseconds) */
void div_timespec(struct timespec *t)
{
	t->tv_sec = t->tv_sec / 2;
	t->tv_nsec = t->tv_nsec / 2;
}
/* end of function */


/* Function for the construction of Ethernet frame header */
void construct_packet(unsigned char * packet)
{
	struct ethhdr *eth;
	int len=sizeof(struct ethhdr);
	
	eth=(struct ethhdr *)malloc(sizeof(struct ethhdr));

        /* Source address (Slave) */	
	eth->h_source[0]=0x00;
	eth->h_source[1]=0x1F;
	eth->h_source[2]=0xD0;
	eth->h_source[3]=0x3F;
	eth->h_source[4]=0x28;
	eth->h_source[5]=0x8C;
	


	/* Destination address (Master) */
	eth->h_dest[0]=0x00;
	eth->h_dest[1]=0x1F;
	eth->h_dest[2]=0xD0;
	eth->h_dest[3]=0x3F;
	eth->h_dest[4]=0x28;
	eth->h_dest[5]=0x52;
		
	eth->h_proto=0x00;

	memcpy(packet,eth,len);	
}
/* end of function */
	


/* Function for setting System time */
void set_time(struct timespec set)
{
	
	int rawsock,i;
	
	rawsock = socket(PF_PACKET,SOCK_RAW,ETH_P_ALL);
	
	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))== -1)
	{
		printf("\n\tError in socket");
		exit(0);
	}
	if((i=ioctl(rawsock,SIOCDEVPRIVATE+1,&set))<0)  //call to ioctl for setting time
	{
		printf("\n\tError in ioctl");
		exit(0);
	}

}
/* end of function */




/* callback function that is passed to pcap_loop(..) and called each time  a packet is recieved */
void my_callback(u_char *useless,const struct pcap_pkthdr* pkthdr,const u_char* packet)
{
      
	struct timespec now,set1,temp,send_curr,factor;
	unsigned long sec;
	char str[200],str1[200],*p,*q,*d,*a,*b;
	char errbuf[PCAP_ERRBUF_SIZE];
	int id,i;
	unsigned char * packet1;
	pcap_t* descr1;
	char *dev;

	
	p = (char *)malloc(100);
	q = (char *)malloc(100);
	a=(char*)malloc(100);	
        b=(char*)malloc(100);	
	
	packet1=(char *)malloc(1514);
		
	strcpy(str,packet+14);
	
	p = strtok(str," ");	
	if(strcmp(p,"ERROR") != 0)
		{
			q = strtok(NULL,"\0");
			strcpy(str1,q);
		}
		
	if(strcmp(p,"SYN")==0)
	{
		
		strcpy(str,str1);
		p = strtok(str,".");
		q = strtok(NULL,"\0");	
		strcpy(str1,q);
		id = atoi(p);

	
		if(id==1)
		{
			
			/* Get timestamps : T1 and T2 */			
			strcpy(a,str1);
			a = strtok(a,".");
			b = strtok(NULL,"\0");
			t1.tv_sec = atol(a);
			t1.tv_nsec = atol(b);
			t2.tv_sec=pkthdr->ts.tv_sec;
			t2.tv_nsec = pkthdr->ts.tv_usec;
		}
		else if(id==3)
		{
			/* Send ACK for T4 */
			dev = pcap_lookupdev(errbuf);
			if(dev == NULL)
			{ 
				printf("%s\n",errbuf); 
				exit(1); 
    			}
			
			descr1 = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    			if(descr1 == NULL)
			{ 
				printf("\tpcap_open_live(): %s\n",errbuf); 
				exit(1); 
    			}
			construct_packet(packet1);	
			strcpy(str,"REP 4.");
			memcpy(packet1+14,str,sizeof(str));
			i=pcap_sendpacket(descr1,packet1,1514);

			if(i==-1)
			{
				printf("\nError in inject function!!!\n");
			}
			
			/* Get timestamp : T4 */
			strcpy(a,str1);
			a = strtok(a,".");
			b = strtok(NULL,"\0");
			t4.tv_sec = atol(a);
			t4.tv_nsec = atol(b);
			pcap_close(descr1);
		}
			
	}/* outer if */
	
	else if(strcmp(p,"ERROR")==0)
		{
		printf("\n\tT4 not received in time........\n");
		printf("\n\tError packet received from sender");
		exit(0);
		}	

	else
		printf("\n\tNot a SYN or ERROR packet\n");
}
/* end of function */


/* main function */
int main(int argc,char **argv)
{ 
	int i,rawsock;
	char *dev,str[10],str1[100];
 	char errbuf[PCAP_ERRBUF_SIZE];
	unsigned char * packet1;
	char *a,*b,*p;
	
    	struct pcap_pkthdr hdr;     /* pcap.h */
    	struct ether_header *eptr;  /* net/ethernet.h */
 	struct timespec temp,temp1,tim;
    	struct ifreq ifr;
	struct timespec estimate,res;
	/* For setting signal handler */	
	struct sigaction myAction;       
	struct itimerval timer;
    	
    	FILE *fp;
	pcap_t *descr1;
	estimate.tv_sec=0;
	estimate.tv_nsec=50000000;
	

	a = (char *)malloc(300);
	p = (char *)malloc(300);
	b = (char *)malloc(300);
	
	packet1=(char *)malloc(1514);

   
    
	/* grab a device to peak into... */
    	dev = pcap_lookupdev(errbuf);
    	if(dev == NULL)
    	{ 
		printf("%s\n",errbuf); 
		exit(1);
	} 

    	/* open device for reading */
    	descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    	if(descr == NULL)
    	{ 
		printf("\tpcap_open_live(): %s\n",errbuf); 
		exit(1); 
    	}

	construct_packet(packet1);	
	strcpy(str,"INIT ");
	memcpy(packet1+14,str,sizeof(str));

	/*Sending INIT packet */
	i=pcap_sendpacket(descr,packet1,1514);
	if(i==-1)
	{
		printf("\n\tError in inject function!!!\n");
	}

		memset(&myAction,0,sizeof(struct sigaction));
		myAction.sa_handler = CatchAlarm;

		/* block everything in handler */
    		if (sigfillset(&myAction.sa_mask) < 0) 
        		printf("\tsigfillset() failed");
    		myAction.sa_flags = 0;

    		if (sigaction(SIGALRM, &myAction, 0) < 0)
        		printf("\tsigaction() failed for SIGALRM");

		alarm(TIMEOUT_SECS);
		pcap_setdirection(descr,PCAP_D_IN);	

 	/* Wait for the packet containing T1 */   	
	i=pcap_loop(descr,1,my_callback,NULL);   
	if(i==-1)
			printf("\n\n\tError in pcap_loop");
		else if(i==-2)
		{
			printf("\n\tT1 not received in time.... exiting");
			exit(0);
			
				
		}
		else
		{
			alarm(0);
			printf("\n\n\n\n\n\tSync packet (T1) received at time T2.....\n");
		}

	     pcap_close(descr);
	descr = pcap_open_live(dev,BUFSIZ,0,-1,errbuf);
    	if(descr == NULL)
    	{ 
		printf("\tpcap_open_live(): %s\n",errbuf); 
		exit(1); 
    	}
	
	construct_packet(packet1);	
	strcpy(str,"SYN 2.");
	memcpy(packet1+14,str,sizeof(str));
	
	/* Send delay_request packet */

	i=pcap_sendpacket(descr,packet1,1514);

	if(i==-1)
	{
		printf("\n\tError in inject function!!!\n");
	}
		printf("\n\tDelay request packet sent at time T3.....\n");

	
	/* Wait for delay response packet(T4) */
	memset(&myAction,0,sizeof(struct sigaction));
		myAction.sa_handler = CatchAlarm;

		/* block everything in handler */
    		if (sigfillset(&myAction.sa_mask) < 0) 
        		printf("\tsigfillset() failed");
    		myAction.sa_flags = 0;

    		if (sigaction(SIGALRM, &myAction, 0) < 0)
        		printf("\tsigaction() failed for SIGALRM");

		alarm(TIMEOUT_SECS);
		pcap_setdirection(descr,PCAP_D_IN);
		i=pcap_loop(descr,1,my_callback,NULL);
		if(i==-1)
			printf("\n\n\tError in pcap_loop");
		else if(i==-2)
		{
			printf("\n\tT4 not received in time... exiting");
                  	exit(0);
		}
		else
		{
			alarm(0);
			printf("\n\tDelay response packet (T4) received in time.....\n");
		}

		pcap_close(descr);// closeing the packet descriptor	

	printf("\n\n\t\t\t\tTIMESTAMPS ARE  : \n");
	printf("\n\tT1 = %ld.%ld\n",t1.tv_sec,t1.tv_nsec);
	printf("\n\tT2 = %ld.%ld\n",t2.tv_sec,t2.tv_nsec);
	printf("\n\tT3 = %ld.%ld\n",t3.tv_sec,t3.tv_nsec);
	printf("\n\tT4 = %ld.%ld\n",t4.tv_sec,t4.tv_nsec);

	
	
	/* Calculate Offset */
	/* Offset  = ((t2-t1)-(t4-t3))/2 */	
	sub_timespec(&t2,&t1,&temp);
	sub_timespec(&t4,&t3,&temp1);
	sub_timespec(&temp,&temp1,&offset);
	div_timespec(&offset);

	printf("\n\n\tOffset : %ld.%ld\n\n",offset.tv_sec,offset.tv_nsec);

	
	/* Create a raw socket for IOCTL */
	rawsock = socket(PF_PACKET,SOCK_RAW,ETH_P_ALL);
	
	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))== -1)
	{
		printf("\n\tError in socket");
		exit(0);
	}
	
	/* IOCTL for getting System time */
	if((i=ioctl(rawsock,SIOCDEVPRIVATE,&ifr))<0)
	{
		printf("\n\terror in ioctl");
		exit(0);
	}

	fp=fopen("/proc/buffer1k","r");
        if(fp==NULL)
	 	printf("\nError opening file");
	else
	{
	 	p = fgets(str1,200,fp);
	}
	
	fclose(fp);	
	strcpy(a,str1);
	a = strtok(a,".");
	b = strtok(NULL,"\0");
	tim.tv_sec = atol(a);
	tim.tv_nsec = atol(b);

	/* Adjust Slave's system time according to the offset */	
	if(offset.tv_sec < 0)
	{
		offset.tv_sec *= -1;
		add_timespec(&tim,&offset,&temp);
		set_time(temp);
	}
	else
	{
		//sub_timespec(&offset,&estimate,&temp);
		sub_timespec(&tim,&offset,&temp);
		//sub_timespec(&temp,&estimate,&res);		
		set_time(temp);
	}
		
	
	return 0;
}
/* end of main function */


