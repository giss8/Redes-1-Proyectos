
const char *byte_to_binary(unsigned short i){
	static char  b[9];
	b[0]= '\0';
	int z;
	for(z = 128; z>0; z>>=1){
		strcat(b,((i&z) == z)? "1" : "0");
	}
	return b;
	free(b);
}

const char *Trama7(unsigned short i){
	static char  b[9];
	b[0]= '\0';
	int z;
	for(z = 64; z>0; z>>=1){
		strcat(b,((i&z) == z)? "1" : "0");		
	}
	return b;
	free(b);
}

const char *Trama2(unsigned short i){
	static char  b[3];
	b[0]= '\0';
	int z;
	for(z = 3; z>0; z>>=1){
		strcat(b,((i&z) == z)? "1" : "0");		
	}
	return b;
	free(b);
}

const char *Trama3(unsigned short i){
	static char  b[4];
	b[0]= '\0';
	int z;
	for(z = 4; z>0; z>>=1){
		strcat(b,((i&z) == z)? "1" : "0");		
	}
	return b;
	free(b);
}

const char *Trama1(unsigned short i){
	static char  b[2];
	b[0]= '\0';
	int z;
	for(z = 1; z>0; z>>=1){
		strcat(b,((i&z) == z)? "1" : "0");		
	}
	return b;
	free(b);
}

void Protocolo(unsigned short i){
	printf("Protocolo SAP: ");
	if(i==0)
		printf("NULL SAP\n");
	else if(i==4)
		printf("SNA\n");
	else if(i==5)
		printf("SNA\n");
	else if(i==6)
		printf("TCP\n");
	else if(i==8)
		printf("SNA\n");
	else if(i==12)
		printf("SNA\n");
	else if(i==66)
		printf("spanning tree\n");
	else if(i==127)
		printf("ISO IEEE 802.2\n");
	else if(i==128)
		printf("XNS\n");
	else if(i==170)
		printf("SNAP\n");
	else if(i==224)
		printf("IPX\n");
	else if(i==240)
		printf("NETBIOS\n");
	else if(i==248)
		printf("RPL\n");
	else if(i==252)
		printf("RPL\n");
	else if(i==254)
		printf("OSI\n");
	else if(i==255)
		printf("Global SAP\n");
	else 
		printf("NULL\n");
}

void IEEE_Trama(u_char *temp1, const struct pcap_pkthdr *header, const u_char *pkt_data){
    u_int i=0,j=0,k=0;

    /*
     * Unused variable
     */
    (VOID)temp1;

    /* print pkt timestamp and pkt len */
    printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);          
    
    /* Print the packet */
    for (i=1; (i < header->caplen + 1 ) ; i++)
    {
        printf("%.2x ", pkt_data[i-1]);
        if ( (i % LINE_LEN) == 0) printf("\n");
    }
    
    printf("\nMAC destino:\n");
	for(j=0;j<6;j++){
	   printf("%02X ",pkt_data[j]);   
	}
	printf("\nMAC origen:\n");
	for(k=6;k<12;k++){
	   printf("%02X ",pkt_data[k]);   
	}
	
    unsigned short tipo = (pkt_data[12]*256)+pkt_data[13];
    printf("\nSIZE: %d   %02X %02X \n",tipo,pkt_data[12],pkt_data[13]);
    
    unsigned short DSAP= pkt_data[14];
    printf("\nCampo DSAP: %s\t%02X\nIoG:%d\t", byte_to_binary(DSAP),DSAP,DSAP&0x01);
    if(strcmp(Trama1(DSAP&0x01), "0")== 0){
    	puts("Individual");
	}
	else{
		puts("Grupo");
	}
	Protocolo(DSAP);
	DSAP = DSAP >> 1;
	printf("Direccion Destino: %s\n\n",Trama7(DSAP&0x7f));
    
    unsigned short SSAP= pkt_data[15];
    printf("\nCampo SSAP: %s\t%02X\nCoR:%d\t", byte_to_binary(SSAP),SSAP,SSAP&0x01);
    if(strcmp(Trama1(SSAP&0x01), "0")== 0){
    	puts("Comando");
	}
	else{
		puts("Respuesta");
	}
    Protocolo(SSAP);
   	SSAP = SSAP >> 1;
	printf("Direccion origen: %s\n\n",Trama7(SSAP&0x7f));
	
    if(tipo<1500){
		printf("CAMPO LONGITUD\n");
    	if(tipo<=3){
    		printf("MODELO NORMAL\n");
    		unsigned short Cp = pkt_data[16]>>1;
    		unsigned short C = pkt_data[16]&0x01;
    		if(C==0){
				printf("Trama I\n");
    			unsigned short TI= pkt_data[16];
    			unsigned short TI_copia= TI;
    			unsigned short TI_copia_1= TI;
    			printf("Trama I: %s\t%02X\n", byte_to_binary(TI),TI);
    			TI = TI >> 1;
				printf("Numero de secuencia solicitada: %s\n",Trama3(TI&0x07));
				TI_copia = TI_copia >> 4;
    			printf("P/F: %d\n", TI_copia&0x01);
    			TI_copia_1 = TI_copia_1 >>5;
				printf("Numero de secuencia esperada: %s\n",Trama7(TI&0x7f));	
    		}
			else{
				Cp=Cp&0x01;
				if(Cp==0){
					unsigned short TS= pkt_data[16];
    				unsigned short TS_copia= TS;
    				unsigned short TS_copia_1= TS;
    				unsigned short TS_copia_2= TS;
    				printf("Trama S: %s\t%02X\n", byte_to_binary(TS),TS);
    				printf("S: %d\n", TS&0x03);
					TS_copia = TS_copia>>2;
					printf("Codigo Trama S: %s\n",Trama3(TS&0x03));
					if(strcmp(Trama2(TS&0x03), "00")== 0)
						printf("Listo para recibir(RR)\n");
					else if(strcmp(Trama2(TS&0x03), "01")== 0 )
						printf("Receptor no listo para recibir(RNR)");
					else if(strcmp(Trama2(TS&0x03), "10")== 0 )
						printf("Rechazo(REJ)");
					else if(strcmp(Trama2(TS&0x03), "11")== 0 )
						printf("Rechazo selectivo(SREJ)");
					TS_copia_1 = TS_copia_1>>4;
    				printf("P/F: %d\n", TS_copia&0x01);
    				TS_copia_2 = TS_copia_2>>5;
					printf("Numero de secuencia esperada: %s\n",Trama7(TS_copia_2&0x7f));	
					
				}
				else{
					printf("Control\n");
					unsigned short TU = pkt_data[16];
					unsigned short TU_copia= TU;
					unsigned short TU_copia_1 = TU;
					unsigned short TU_copia_2 = TU;
					unsigned short CR= pkt_data[15];
					printf("Trama U: %s\t%02X\n",byte_to_binary(TU),TU);
					printf("U: %s\n",Trama2(TU&0x03));
					TU_copia = TU_copia >> 2;
					TU_copia_1 = TU_copia_1 >> 5;
					TU_copia_2 = TU_copia_2 >> 4;
					printf("P/F: %d\n", TU_copia_2&0x01);
					
					printf("Codigo Trama U: %s ",Trama3(TU_copia_1&0x07));
					printf("%s\n",Trama2(TU_copia&0x03));	
					
					if(strcmp(Trama1(CR&0x01), "0")== 0 && strcmp(Trama1(TU_copia_2&0x01), "1") == 0){
    					printf("Comando con Protocolo: ");
    					if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("SNRM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "110")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SNRME");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SABM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SABME");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UI");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "010")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("DISC");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("SIM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UP");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("RSET");
						else if(strcmp(Trama3(TU_copia_1&0x07), "101")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("XID");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("FRMR");
					}
					else if(strcmp(Trama1(CR&0x01), "1")== 0 && strcmp(Trama1(TU_copia_2&0x01), "1") == 0){
						printf("Respuesta con Protocolo: ");
    					if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "110")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("DM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UI");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UA");
						else if(strcmp(Trama3(TU_copia_1&0x07), "010")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("RD");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("RIM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "101")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("XID");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("FRMR");
					}
					else
						puts("El bit P/F esta apagado");
										
				}
			}
		}
    	else{
    		printf("MODELO EXTENDIDO\n");
            unsigned short Ccp = pkt_data[16]>>1;
    		unsigned short C1 = pkt_data[16]&0x01;
			if(C1==0){
				printf("Trama I\n");
    			unsigned short TI_p1 = pkt_data[16];
    			unsigned short TI_p2 = pkt_data[17];
    			unsigned short TI_copia_p1 = TI_p1&0x01;
    			unsigned short TI_copia_p2 = TI_p2;
				printf("Trama I: %s  ", byte_to_binary(TI_p1));
    			printf("%s\t%02X %02X\n", byte_to_binary(TI_p2), TI_p1, TI_p2);
    			printf("I: %d\n",TI_p1&0x01);
    			TI_p1 = TI_p1 >> 1;
				printf("Numero de secuencia solicitada: %s\n",Trama7(TI_p1&0x7f));
    			printf("P/F: %d\n", TI_p2&0x01);
    			TI_copia_p2 = TI_copia_p2 >> 1;
				printf("Numero de secuencia esperada: %s\n",Trama7(TI_copia_p2&0x7f));	
			}
			else{
				Ccp=Ccp&0x01;
				if(Ccp==0){
					printf("Trama S\n");	
					unsigned short TS_p1 = pkt_data[16];
					unsigned short TS_p2 = pkt_data[17];
					unsigned short TS_copia_p1 = TS_p1;
					unsigned short TS_copia_p2 = TS_p2;
					unsigned short TS_copia_p3 = TS_p2;
					unsigned short TS_copia_p4 = TS_p1;
					printf("Trama S: %s  ",byte_to_binary(TS_p1));
					printf("%s\t%02X %02X\n", byte_to_binary(TS_p2), TS_p1, TS_p2);
					printf("S: %s\n",Trama2(TS_p1&0x03));
					TS_copia_p1 = TS_copia_p1 >> 2;
					printf("Codigo Trama S: %s\t",Trama2(TS_copia_p1&0x03));
					
					if(strcmp(Trama2(TS_copia_p1&0x03), "00")== 0)
						printf("Listo para recibir(RR)\n");
					else if(strcmp(Trama2(TS_copia_p1&0x03), "01")== 0 )
						printf("Receptor no listo para recibir(RNR)\n");
					else if(strcmp(Trama2(TS_copia_p1&0x03), "10")== 0 )
						printf("Rechazo(REJ)\n");
					else if(strcmp(Trama2(TS_copia_p1&0x03), "11")== 0 )
						printf("Rechazo selectivo(SREJ)\n");
					
	   				printf("P/F: %d\n", TS_p2&0x01);
    				TS_copia_p2 = TS_copia_p2 >> 1;
					printf("Numero de secuencia esperada: %s\n",Trama7(TS_copia_p2&0x7f));		
				}
				else{
					unsigned short TU = pkt_data[16];
					unsigned short TU_copia= TU;
					unsigned short TU_copia_1 = TU;
					unsigned short TU_copia_2 = TU;
					printf("Trama U: %s\t%02X\n",byte_to_binary(TU), TU);
					printf("U: %s\n",Trama2(TU&0x03));
					TU_copia = TU_copia >> 2;
					TU_copia_1 = TU_copia_1 >> 5;
					TU_copia_2 = TU_copia_2 >> 4;
					printf("P/F: %d\n", TU_copia_2&0x01);
					printf("Codigo Trama U: %s ",Trama3(TU_copia_1&0x07));
					printf("%s\n",Trama2(TU_copia&0x03));	
					
					if((strcmp(Trama1(SSAP&0x01), "0")== 0 && strcmp(Trama1(TU_copia_2&0x01), "1") == 0)){
    					printf("Comando con Protocolo: ");
    					if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("SNRM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "110")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SNRME");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SABM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("SABME");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UI");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "010")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("DISC");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("SIM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UP");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("RSET");
						else if(strcmp(Trama3(TU_copia_1&0x07), "101")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("XID");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("FRMR");
					}
					else if(strcmp(Trama1(SSAP&0x01), "1")== 0 && strcmp(Trama1(TU_copia_2&0x01), "1") == 0){
						printf("Respuesta con Protocolo: ");
    					if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "110")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("DM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UI");
						else if(strcmp(Trama3(TU_copia_1&0x07), "011")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("UA");
						else if(strcmp(Trama3(TU_copia_1&0x07), "010")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("RD");
						else if(strcmp(Trama3(TU_copia_1&0x07), "000")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("RIM");
						else if(strcmp(Trama3(TU_copia_1&0x07), "001")== 0 && strcmp(Trama2(TU_copia&0x03), "00")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("NULL");
						else if(strcmp(Trama3(TU_copia_1&0x07), "101")== 0 && strcmp(Trama2(TU_copia&0x03), "11")== 0 )
							printf("XID");
						else if(strcmp(Trama3(TU_copia_1&0x07), "100")== 0 && strcmp(Trama2(TU_copia&0x03), "01")== 0 )
							printf("FRMR");
					}
					else
						puts("El bit P/F esta apagado\n");
					
				}
			}
		}
	}	
    else
    	printf("CAMPO TIPO\n");
}
