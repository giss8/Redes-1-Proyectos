//interfaz 3
#ifdef _MSC_VER
/*
 * we do not want the warnings about the old deprecated and unsecure CRT functions
 * since these examples can be compiled under *nix as well
 */
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <pcap.h>
#include <string.h>

/* 4 bytes IP address */
typedef struct ip_address{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
	u_char ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_address saddr; // Source address
	ip_address daddr; // Destination address
	u_int op_pad; // Option + Padding
}ip_header;

/* ICMP header*/
typedef struct icmp_header{
	u_char type; // ICMP type
	u_char code; // ICMP code
	u_short crc; // Checksum
}icmp_header;

/* IGMPv3 header*/
typedef struct igmp_header{
	u_char type; // IGMP type
	u_char rsv1; // reserved
	u_short crc; // Checksum
	u_short rsv2; // reserved
	u_short ngr; // #group records (al menos 1)
}igmp_header;

/* TCP header*/
typedef struct tcp_header{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int sec_num; // secuence number	
	u_int ack_num; // ack number
	u_char d_offset_rsv; // 4bit data offset +4bit reserved
	u_char flags; // TCP flags
	u_short window; // window
	u_short crc; // Checksum
	u_short upointer; // urgent pointer
}tcp_header;

/* UDP header*/
typedef struct udp_header{
	u_short sport; //Source port
	u_short dport; //Destination port
	u_short len; //length
	u_short crc; //Checksum
}udp_header;

/* prototype of the packet handler */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr,"Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i==0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1-%d):",i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs, i=0; i< inum-1 ;d=d->next, i++);
	
	/* Open the device */
	/* Open the adapter */
	if ((adhandle= pcap_open_live(d->name,	// name of the device
							 65536,			// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
							 1,				// promiscuous mode (nonzero means promiscuous)
							 1000,			// read timeout
							 errbuf			// error buffer
							 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 15, packet_handler, NULL);
	
	pcap_close(adhandle);
	return 0;
}


/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*unused parameters*/
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	
	printf("***************************************************************************************\n");
	printf("***************************************************************************************\n");
	printf("***************************************************************************************\n");
	
	int i;
    for (i=1; (i < header->caplen + 1 ) ; i++){
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % 16) == 0) printf("\n");
    }
    
    printf("\nMAC destino: ");
	for(i=0;i<6;i++){
	   printf("%02X:",pkt_data[i]);   
	}
	printf("\nMAC origen: ");
	for(i=6;i<12;i++){
	   printf("%02X:",pkt_data[i]);   
	}
	
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	
	printf(" \n\n");
    unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
    printf("Tipo: %d   %02X %02X \n",tipo,pkt_data[12],pkt_data[13]);
    if (tipo==2048){
		printf("Paquete IP..\n");
		ip_header *ih;
		u_int ip_len;
		/* retireve the position of the ip header */
		ih = (ip_header *) (pkt_data + 14); //length of ethernet header
		/* print ip addresses and udp ports */
		int j;
	
		printf("Version: ");	
		
		for(j=5;j<9;j++){
			printf("%d",(ih->ver_ihl>>j)&0x01);
		}
		printf("	(%d)\n",(ih->ver_ihl>>4)&0x0f);
		
		char le[4];
	    printf("Header : ");
		for(j=0;j<4;j++){
			le[j] = (ih->ver_ihl>>j)&0x01;
		}
		for(j=3;j>=0;j--)	
			printf("%d",(int)le[j]);
		printf("	(%d)\n",(ih->ver_ihl)&0x0f);
		u_short length = (u_short)((ih->ver_ihl)&0x0f)* (u_short)((ih->ver_ihl>>4)&0x0f);
		printf("Length : %d \n", length);
	
		
		u_short lentotal = ((u_short)((ih->tlen)&0xff)*256) + (u_short)((ih->tlen>>8)&0xff);
		printf("Longitud: %d\n", lentotal);
		
		printf("Servicios Diferenciados: \n");
		for(j=5; j<8; j++)
			printf("%d",(ih->tos>>j)&0x01);
		u_short CSI = (ih->tos)&0xe0;
		
		if(CSI==224)//111
			printf(" (Network Control)");
		else if(CSI==192)//110
			printf(" (Internetwork control)");
		else if(CSI==160)//101
			printf(" (CRITIC/ECP)");
		else if(CSI==128)//100
			printf(" (Flash overrite)");
		else if(CSI==96)//011
			printf(" (Flash)]");
		else if(CSI==64)//010
			printf(" (Immediate)");
		else if(CSI==32)//001
			printf(" (Priority)");
		else if(CSI==0)//000
			printf(" (Routine)");
		else
			printf(" (Unknown)");
			
		printf("\nECN: ");
		for(j=0; j<2; j++)
			printf("%d",(ih->tos>>j)&0x01);
		u_short ECN = (ih->tos)&0x03;
		
		if(ECN==0)//111
			printf(" (Sin capacidad ECN)\n");
		else if(ECN==1)//001
			printf(" (Capacidad de transporte ECN (0))\n");
		else if(ECN==2)//010
			printf(" (Capacidad de transporte ECN (1))\n");
		else if(ECN==3)//011
			printf(" (Congestion encontrada)\n");
		else 
			printf(" (Unknown)\n");
		
		printf("ID: %02X %02X", (ih->identification)&0xff, (ih->identification>>8)&0xff);
		
		printf("\nFlags\nDon't Fragment: %d", (ih->flags_fo>>6)&0x01);
		(ih->flags_fo>>6)&0x01==1? puts(" Encendido"):puts(" Apagado");
		printf("More: %d", (ih->flags_fo>>5)&0x01);
		(ih->flags_fo>>5)&0x01==1? puts(" Encendido"):puts(" Apagado");
		u_short Foffset = ((u_short)((ih->flags_fo<<3)&0x1f)*256) + (u_short)((ih->flags_fo>>8)&0xff);
		printf("Offset: %02X %02X (%02X)", ((ih->flags_fo<<3))&0x1f, (ih->flags_fo>>8)&0xff, Foffset);
		
		printf("\nTTL: %02X (%d)", ih->ttl,ih->ttl);
		
		printf("\nProtocolo: %02X ", ih->proto);
		
		if(ih->proto==0)
			printf("Reserved");
		else if(ih->proto==1)
			printf("ICMP");
		else if(ih->proto==2)
			printf("IGMP");
		else if(ih->proto==6)
			printf("TCP");
		else if(ih->proto==17)
			printf("UDP");
		else 
			printf("Other");
		
		printf("\nChecksum: %02X %02X", (ih->crc)&0xff, (ih->crc>>8)&0xff);
		
		printf("\nSource IP Address: %d.%d.%d.%d\nDestination IP Address: %d.%d.%d.%d\n",ih->saddr.byte1,ih->saddr.byte2,ih->saddr.byte3,ih->saddr.byte4,ih->daddr.byte1,ih->daddr.byte2,ih->daddr.byte3,ih->daddr.byte4);
		
		if(ih->proto==0)
			printf("Protocol Reserved");
		else if(ih->proto==1){
			printf("Protocol ICMP");
			icmp_header *icmp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			icmp = (icmp_header *) (pkt_data + 14+(ihl));
			printf("Tipo: %d\n",icmp->type);
			printf("Codigo:%d\n", icmp->code);
			
			if(icmp->type==0){
				printf("Echo Reply");
				if(icmp->code==0)
					printf("Echo Reply");
			}
			else if(icmp->type==3){
				printf("Destination unreachable");
				if(icmp->code==0)
					printf("Destination network unreachable");
				else if(icmp->code==1)
					printf("Destination host unreachable");
				else if(icmp->code==2)
					printf("Destination protocol unreachable");
				else if(icmp->code==3)
					printf("Destination port unreachable");
				else if(icmp->code==4)
					printf("Fragmetation needed and DF flag set");
				else
					printf("Source route failed");
			}
			else if(icmp->type==5){
				printf("Redirect Message");//4
				if(icmp->code==0)
					printf("Redirect datagram for the Network");
				else if(icmp->code==1)
					printf("Redirect datagram for the host");
				else if(icmp->code==2)
					printf("Redirect datagram for the Type of Service and Network");
				else
					printf("Redirect datagram for the Service and Host");
			}
			else if(icmp->type==8){
				printf("Echo Request");
				if(icmp->code==0)
					printf("Echo request");
			}
			else if(icmp->type==9){
				printf("Router Advertisement");
				if(icmp->code==0)
					printf("Use to discover the addresses of operational routers");				
			}
			else if(icmp->type==10){
				printf("Router Solicitation");
				if(icmp->code==0)
					printf("Use to discover the addresses of operational routers");
			}
			else if(icmp->type==11){
				printf("Time Exceeded");//2
				if(icmp->code==0)
					printf("Time to live exceeded in transit");
				else
					printf("Fragment reassembly time exceeded"); 
			}
			else if(icmp->type==12){
				printf("Parameter Problem");//3
				if(icmp->code==0)
					printf("Pointer indicates error");
				else if(icmp->code==1)
					printf("Missing required option");
				else
					printf("Bad length");
			}
			else if(icmp->type==13){
				printf("Timestamp");
				if(icmp->code==0)
					printf("Used for time synchronization");
			}
			else if(icmp->type==14){
				printf("Timestamp Reply");
				if(icmp->code==0)
					printf("Reply to Timestamp message");
			}
			else
				printf("Unknown");
				
			printf("Checksum: %02X %02X\n", (icmp->crc)&0xff, (icmp->crc>>8)&0xff);
		}
		else if(ih->proto==2){
			igmp_header *igmp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			igmp = (igmp_header *) (pkt_data + 14+(ihl));
			printf("Protocol IGMP");
			printf("Tipo: %02X", igmp->type);
			printf("Reserved: %02X", igmp->rsv1);
			printf("Checksum: %02X", igmp->crc);
			printf("Reserved: %02X", igmp->rsv2);
			printf("Group: %02X", igmp->ngr);
		}	
		else if(ih->proto==6){
			printf("Protocol TCP");
			tcp_header *tcp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;        
			tcp = (tcp_header *) (pkt_data + 14+(ihl));
			printf("\n---->Source port: %02X %02X\n",(tcp->sport)&0xff, (tcp->sport>>8)&0xff);
			printf("---->Destination port: %02X %02X\n",(tcp->dport)&0xff, (tcp->dport>>8)&0xff);
			printf("---->Secuense number: %02X %02X %02X %02X\n",(tcp->sec_num)&0xff, (tcp->sec_num>>8)&0xff,(tcp->sec_num>>16)&0xff,(tcp->sec_num>>24)&0xff);
			printf("---->Ack number: %02X %02X %02X %02X\n",(tcp->ack_num)&0xff, (tcp->ack_num>>8)&0xff,(tcp->ack_num>>16)&0xff,(tcp->ack_num>>24)&0xff);
			printf("---->Checksum: %02X %02X\n", (tcp->crc)&0xff, (tcp->crc>>8)&0xff);
			printf("---->Data Offset: %d\n", (tcp->d_offset_rsv>>4)&0x0f);
			printf("\tFlags: ");
			for(j=7; j>=0; j--)
				printf("%d", (tcp->flags>>j)&0x01);
			printf("\t");
			if((tcp->flags)&0x01==1)
				printf("CWR ");
			if((tcp->flags>>1)&0x01==1)
				printf("ECE ");
			if((tcp->flags>>2)&0x01==1)
				printf("URG ");
			if((tcp->flags>>3)&0x01==1)
				printf("ACK ");
			if((tcp->flags>>4)&0x01==1)
				printf("PSH ");
			if((tcp->flags>>5)&0x01==1)
				printf("RST ");
			if((tcp->flags>>6)&0x01==1)
				printf("SYN ");
			if((tcp->flags>>7)&0x01==1)
				printf("FIN ");
			printf("\nUrgent Pointer: %02X  %02X\n",(tcp->upointer)&0xff, (tcp->upointer>>8)&0xff);
		}	
		else if(ih->proto==17){
			printf("Protocol UDP");
			udp_header *udp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			udp = (udp_header *) (pkt_data + 14+(ihl));
			printf("\n---->Source port: %02X %02X\n",(udp->sport)&0xff, (udp->sport>>8)&0xff);
			printf("---->Secuense number: %02X %02X\n",(udp->dport)&0xff, (udp->dport>>8)&0xff);
			printf("---->Length: %02X %02X\n", (udp->len)&0xff, (udp->len>>8)&0xff);
			printf("---->Checksum: %02X %02X\n", (udp->crc)&0xff, (udp->crc>>8)&0xff);
		}
		else 
			printf("Other Protocol");
	}
	else 
		printf("No es IP...\n");
}


