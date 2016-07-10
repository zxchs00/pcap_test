
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>

#define PROMISCUOUS 1
/*
#define PCAP_CNT_MAX 10
#define PCAP_SNAPSHOT 1024
#define PCAP_TIMEOUT 100

void packet_view(unsigned char *, const struct pcap_pkthdr *, const unsigned char *);
*/

int main(void){

	char* device = NULL;// = "eth0";
	pcap_t* pd;
	int i;
	int snaplen = 100;
	char ebuf[PCAP_ERRBUF_SIZE];

	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	int len,res;

	if(device == NULL){
		if( (device = pcap_lookupdev(ebuf)) == NULL){
			perror(ebuf);
			exit(-1);
		}
	}
	printf("%s Scanning\n", device);

	pd = pcap_open_live(device, snaplen, PROMISCUOUS, 1000, ebuf);
	if(pd == NULL){
		perror(ebuf);
		exit(-1);
	}

	while((res = pcap_next_ex( pd, &header, &pkt_data)) >= 0){

		if(res == 0)
		/* Timeout elapsed */
			continue;

		len = 0;
		/* packet check
		printf("PACKET\n");
		while(len < header->len) {
			printf("%02x ", *(pkt_data++));
			if(!(++len % 16))
				printf("\n");
		}
		printf("\n");
		for(i=0;i<len;i++){
			pkt_data--;
		}
		*/
		printf("     Source Mac   ");
		printf("%02x",pkt_data[6]);
		for(i=7;i<12;i++){
			printf(":");
			printf("%02x", pkt_data[i]);
		}
		printf("\n");
		printf("Destination Mac   ");
		printf("%02x",pkt_data[0]);
		for(i=1;i<6;i++){
			printf(":");
			printf("%02x", pkt_data[i]);
		}
		printf("\n");

		// type check
		if( ntohs(*((unsigned short*)(&pkt_data[12]))) != 0x0800 ){
			printf("Type is not IPv4!\n");
			continue;
		}
		else{ // It's IPv4 !
			printf("     Source IP    %d",pkt_data[14+12]);
			for(i=1;i<4;i++){
				printf(".%d",pkt_data[14+12+i]);
			}
			printf("\nDestination IP    %d",pkt_data[14+16]);
			for(i=1;i<4;i++){
				printf(".%d",pkt_data[14+16+i]);
			}
			printf("\n");

			// protocol check
			if( pkt_data[14+9] != 0x06 ){
				printf("Protocol is not TCP!\n\n");
				continue;
			}
			else{ // It's TCP !
				printf("     Source Port  %d\n",ntohs(*((unsigned short*)(&pkt_data[34]))));
				printf("Destination Port  %d\n\n",ntohs(*((unsigned short*)(&pkt_data[36]))));
			}

		}

	}

	if(res == -1){
		printf("Error reading the packets: %s\n", pcap_geterr(pd));
		return -1;
	}

// using pcap_loop

/*
	if(pcap_loop(pd, PCAP_CNT_MAX, packet_view, 0) < 0) {
		perror(pcap_geterr(pd));
		exit(1);
	}
*/

	pcap_close(pd);
	exit(0);

	return 0;
}

// using pcap_loop

/*
void packet_view(unsigned char *user, const struct pcap_pkthdr *h, const unsigned char *p){
	int len;

	len = 0;

	printf("PACKET\n");
	while(len < h->len) {
		printf("%02x ", *(p++));
		if(!(++len % 16))
			printf("\n");
	}
	printf("\n");

	return ;
}
*/


/* Compile
	gcc -o df_LHS_network df_LHS_network.c -lpcap

   Execute
	sudo ./df_LHS_network
*/