
/* IGMPv3 header*/
typedef struct igmp_header{
	u_char type; // IGMP type
	u_char rsv1; // reserved
	u_short crc; // Checksum
	u_short rsv2; // reserved
	u_short ngr; // #group records (al menos 1)
}igmp_header;

void IGMP_Trama(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
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
	printf("\n"); 
	printf("-------------------------------------------------------------------------------------------------------------------\n\n"); 
	
	int i;
    for (i=1; (i < header->caplen + 1 ) ; i++){
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % 16) == 0) printf("\n");
    }
    
    printf("\nMAC destination: ");
	for(i=0;i<6;i++){
	   printf("%02X:",pkt_data[i]);   
	}
	printf("\nMAC source: ");
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
		for(j=5;j<9;j++){
			printf("%d",(ih->ver_ihl>>j)&0x01);
		}
		printf(" .... = Version: ");
		printf("%d",(ih->ver_ihl>>4)&0x0f);
		
		char le[4];
		printf("\n.... ");
		for(j=0;j<4;j++){
			le[j] = (ih->ver_ihl>>j)&0x01;
		}
		for(j=3;j>=0;j--)	
			printf("%d",(int)le[j]);
		
		u_short length = (u_short)((ih->ver_ihl)&0x0f)* (u_short)((ih->ver_ihl>>4)&0x0f);
		printf(" = Header Length : %d bytes ", length);
		printf("(%d)\n",(ih->ver_ihl)&0x0f);
		
		u_short lentotal = ((u_short)((ih->tlen)&0xff)*256) + (u_short)((ih->tlen>>8)&0xff);
		printf("Longitud total: %d\n", lentotal);
		
		printf("Servicios Diferenciados: [precedence: ");
		for(j=5; j<8; j++)
			printf("%d",(ih->tos>>j)&0x01);
		u_short CSI = (ih->tos)&0xe0;
		
		if(CSI==224)//111
			printf(" (Network Control)]");
		else if(CSI==192)//110
			printf(" (Internetwork control)]");
		else if(CSI==160)//101
			printf(" (CRITIC/ECP)]");
		else if(CSI==128)//100
			printf(" (Flash overrite)]");
		else if(CSI==96)//011
			printf(" (Flash)]");
		else if(CSI==64)//010
			printf(" (Immediate)]");
		else if(CSI==32)//001
			printf(" (Priority)]");
		else if(CSI==0)//000
			printf(" (Routine)]");
		else
			printf(" (Unknown)]");
			
		printf(" [ECN: ");
		for(j=0; j<2; j++)
			printf("%d",(ih->tos>>j)&0x01);
		u_short ECN = (ih->tos)&0x03;
		
		if(ECN==0)//111
			printf(" (Sin capacidad ECN)]\n");
		else if(ECN==1)//001
			printf(" (Capacidad de transporte ECN (0))]\n");
		else if(ECN==2)//010
			printf(" (Capacidad de transporte ECN (1))]\n");
		else if(ECN==3)//011
			printf(" (Congestion encontrada)]\n");
		else 
			printf(" (Unknown)]\n");
		
		printf("ID: %02X %02X", (ih->identification)&0xff, (ih->identification>>8)&0xff);
		
		printf("\n----Flags\nDon't Fragment: %d", (ih->flags_fo>>6)&0x01);
		(ih->flags_fo>>6)&0x01==1? puts(" Encendido"):puts(" Apagado");
		printf("More: %d", (ih->flags_fo>>5)&0x01);
		(ih->flags_fo>>5)&0x01==1? puts(" Encendido"):puts(" Apagado");
		u_short Foffset = ((u_short)((ih->flags_fo<<3)&0x1f)*256) + (u_short)((ih->flags_fo>>8)&0xff);
		printf("Fragment offset: %02X %02X (%02X)", ((ih->flags_fo<<3))&0x1f, (ih->flags_fo>>8)&0xff, Foffset);
		
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
		else if(ih->proto==2){
			igmp_header *igmp;
			u_char ihl = ((ih->ver_ihl)&0x0f)*4;
			igmp = (igmp_header *) (pkt_data + 14+(ihl));
			printf("Protocol IGMP");
			printf("\n\tTipo: %02X", igmp->type);
			printf("\n\tReserved: %02X", igmp->rsv1);
			printf("\n\tChecksum: %02X", igmp->crc);
			printf("\n\tReserved: %02X", igmp->rsv2);
			printf("\n\tGroup: %02X", igmp->ngr);
		}	
		else 
			printf("\nOther Protocol");
	}
	else 
		printf("No es IP...\n");
}
