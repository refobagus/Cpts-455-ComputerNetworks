#include <stdio.h>
#include <stdlib.h>
#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <time.h>
#include <fcntl.h>
#include <string.h>

#define SERVER_PORT 5432
#define MAX_LINE 256

int main(int argc, char * argv[])
{
    char *fname;
    char buf[MAX_LINE];
    struct sockaddr_in sin;
    int len;
    int s, i;
    struct timeval tv;
    char seq_num = 1; 
    FILE *fp;
    int line;
    char recv[MAX_LINE+1];
    char send[MAX_LINE+1];
    char payload[MAX_LINE][MAX_LINE]; //line and character of the line

    if (argc==2) {
        fname = argv[1];
    }
    else {
        fprintf(stderr, "usage: ./server_udp filename\n");
        exit(1);
    }


    /* build address data structure */
    bzero((char *)&sin, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_addr.s_addr = INADDR_ANY;
    sin.sin_port = htons(SERVER_PORT);

    /* setup passive open */
    if ((s = socket(PF_INET, SOCK_DGRAM, 0)) < 0) {
        perror("simplex-talk: socket");
        exit(1);
    }
    if ((bind(s, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
        perror("simplex-talk: bind");
        exit(1);
    }

    socklen_t sock_len = sizeof sin;

    fp = fopen(fname, "w");
    if (fp==NULL){
        printf("Can't open file\n");
        exit(1);
    }
    
    while(1){
        memset(recv, 0, sizeof recv);
        len = recvfrom(s, recv, sizeof(recv), 0, (struct sockaddr *)&sin, &sock_len);
        line = recv[0];
        if(len == -1){
            perror("PError");
        } 
        else if(len > 1){
            // if there is a line, then copy to copier
        	strcpy(payload[line], recv+1);
        }   
        else if(len == 1){
            if (recv[0] == 0x02){
                printf("Transmission Complete\n");
                break;
            }
            else{
                perror("Error: Short packet\n");
            }
        }
	    
        
        
        memset(send, 0, sizeof send);
        send[0] = line;
        if(sendto(s, send, strlen(send), 0, (struct sockaddr *)&sin, sock_len)<0){
            perror("SendTo Error\n");
            exit(1);
        }

    }
    
    // payload copier
    i=1;
    while(strlen(payload[i])!=0)
    {
        if(fputs((char *) payload[i], fp) < 1){
            printf("fputs() error\n");
        }
        i++;
    }

    fclose(fp);
    close(s);
}
