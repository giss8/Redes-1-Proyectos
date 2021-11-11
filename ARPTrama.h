
void ARP_Trama(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;

	/*
	 * unused parameters
	 */
	(VOID)(param);
	(VOID)(pkt_data);

	/* convert the timestamp to readable format */
	local_tv_sec = header->ts.tv_sec;
	//ltime=localtime(&local_tv_sec);
	//strftime( timestr, sizeof timestr, "%H:%M:%S", ltime);
	    /* Print the packet */
	int i;
	printf("\n"); 
	printf("-------------------------------------------------------------------------------------------------------------------\n\n"); 
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % 16) == 0) printf("\n");
    }
	
	//printf("%s,%.6d len:%d\n", timestr, header->ts.tv_usec, header->len);
	int j=0,k=0, m=0, n=0, l=0, p=0;
	printf("\nMAC destination: ");
	for(j=0;j<6;j++){
	   printf("%02X:",pkt_data[j]);   
	}
	printf("\nMAC source: ");
	for(k=6;k<12;k++){
	   printf("%02X: ",pkt_data[k]);   
	}
	
	printf(" \n\n");
    unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
    printf("Tipo: %d   %02X %02X \n",tipo,pkt_data[12],pkt_data[13]);
    
    if(tipo==2054){
		printf("Target Protocol Address\n");
		//Tipo de hardware
		printf("\nHardware type: ");
		unsigned short type_Hardware = (pkt_data[14]*256) + pkt_data[15];
		if(type_Hardware==1)
			printf("\n\tEthernet(1)");
		else if(type_Hardware==6)
			printf("\n\tIEEE 802 Networks (6)");
		else if(type_Hardware==7)
			printf("\n\tARC NET");
		else if(type_Hardware==15)
			printf("\n\tFrame Relay (15)");
		else if(type_Hardware==16)
			printf("\n\tATM (Asynchronous Transfer Mode)");
		else if(type_Hardware==17)
			printf("\n\tHDLC");
		else if(type_Hardware==18)
			printf("\n\tFibre Channel");
		else if(type_Hardware==19)
			printf("\n\tATM (Asynchronous Transfer Mode)");
		else if(type_Hardware==20)
			printf("\n\tSerial Line");
		else
			printf("\n\tUnknown");
		printf("\n\n");
		
		//Tipo de protocolo
		printf("Protocol type: ");
		unsigned short type_Protocol = (pkt_data[16]*256) + pkt_data[17];
		if(type_Protocol==2048)
			printf("\n\tIPv4\n");
		else if(type_Protocol==2054)
			printf("\n\tARP\n");
		else
			printf("\n\tUnknown\n");
		
		//Tamaño de hardware 
		printf("\nHardware size: ");
		printf("%d", pkt_data[18]);
		
		//Tamaño de protocolo
		printf("\nProtocol size: ");
		printf("%d", pkt_data[19]);
		
		//Opcode
		printf("\nOpcode: ");
		unsigned short Opcode =(pkt_data[20] *256) + pkt_data[21];
		if(Opcode==1)
			printf("\n\tARP REQUEST (1)\n");
		else if(Opcode==2)
			printf("\n\tARP REPLY (2)\n");
		else if(Opcode==3)
			printf("\n\tRARP REQUEST (3)\n");
		else if(Opcode==4)
			printf("\n\tRARP REPLY (4)\n");
		else
			printf("\n\tUnknown\n");
		
		//MAC address del remitente
		printf("\nSender MAC address: ");
		for(m=22;m<28;m++){
	   		printf("%02X ",pkt_data[m]);   
		}
		
		//IP address del remitente
		printf("\nSender IP address: ");
		for(n=28;n<31;n++){
	   		printf("%d ",pkt_data[n]);   
		}
		printf("%d",pkt_data[31]);
		
		//MAC address del objetivo
		printf("\nTarget MAC address: ");
		for(l=32;l<38;l++){
	   		printf("%02X ",pkt_data[l]);   
		}
		
		printf("\nTarget IP address: ");
		for(p=38; p<41;p++){
	   		printf("%d.",pkt_data[p]);   
		}
		printf("%d\n",pkt_data[41]);
	}
    
}
