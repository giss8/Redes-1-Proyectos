#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <pcap.h>
#include <stdlib.h>
#include <stdio.h>
#define LINE_LEN 16
#define PAQUETES 500

void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data);
void imprimirTrama(const struct pcap_pkthdr *, const u_char *);
void analizarARP(const u_char *);
void imprimirHarwareType(unsigned short);
void imprimirProtocolType(unsigned short);
void imprimirOpcode(unsigned short);
void imprimirMac(const u_char *, int, int);
void imprimirIp(const u_char *, int, int);

//Variables globales
int ARP = 0, noARP = 0;

int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i = 0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	/* Retrieve the device list */
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Jump to the selected adapter */
	for(d=alldevs; d; d=d->next)
	{
		printf("%d. %s", ++i, d->name);
		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}
	
	if(i == 0)
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

	if ((adhandle= pcap_open_live(d -> name,	// name of the device
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
	
	printf("\n\nANALIZADOR DEL PROTOCOLO ARP");
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, PAQUETES, packet_handler, NULL);
	
	printf("\n\n\n\nNumero de tramas ARP encontradas: %d", ARP);
	printf("\nNumero de tramas no ARP encontradas: %d\n", noARP);
	
	pcap_close(adhandle);
	
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */
void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int j = 0, k = 0;
	
	switch ((pkt_data[12] << 8) + pkt_data[13])
	{
		case 2054:
			printf("\n\n\n\nTrama ARP \n\n");
			imprimirTrama(header, pkt_data);
			analizarARP(pkt_data);
			ARP++;
			break;
		default:
			noARP++;
			break;
	}
}

void imprimirTrama(const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	int i;
	
	for (i = 1; (i < header -> caplen + 1); i++)
    {
        printf("%.2x ", pkt_data[i - 1]);
        
        if ( (i % LINE_LEN) == 0) 
			printf("\n");
    }
}

void analizarARP(const u_char *pkt_data)
{
	//MAC destino
	printf("\n\nMAC DESTINO: ");
	imprimirMac(pkt_data, 0, 5);
	    
	//MAC origen
	printf("\nMAC ORIGEN: ");
	imprimirMac(pkt_data, 6, 11);
	 
    printf("\nTipo: ");
    imprimirProtocolType((pkt_data[12] << 8) + pkt_data[13]);
	
	//Tipo de hardware
	printf("\nHardware type: ");
	imprimirHarwareType((pkt_data[14] << 8) + pkt_data[15]);
	
	//Tipo de protocolo
	printf("\nProtocol type: ");
	imprimirProtocolType((pkt_data[16] << 8) + pkt_data[17]);
	
	//Tamaño de hardware 
	printf("\nHardware size: ");
	printf("%d", pkt_data[18]);
	
	//Tamaño de protocolo
	printf("\nProtocol size: ");
	printf("%d", pkt_data[19]);
	
	//Opcode
	printf("\nOpcode: ");
	imprimirOpcode((pkt_data[20] << 8) + pkt_data[21]);
	
	//MAC address del remitente
	printf("\nSender MAC address: ");
	imprimirMac(pkt_data, 22, 27);
	
	//IP address del remitente
	printf("\nSender IP address: ");
	imprimirIp(pkt_data, 28, 31);
	
	//MAC address del objetivo
	printf("\nTarget MAC address: ");
	imprimirMac(pkt_data, 32, 37);
	
	printf("\nTarget IP address: ");
	imprimirIp(pkt_data, 38, 41);
}

void imprimirHarwareType(unsigned short tipo)
{
	switch(tipo)
	{
		case 1:
			printf("Ethernet");
			break;
		case 6:
			printf("IEEE 802 Networks");
			break;
		case 7:
			printf("ARCNET");
			break;
		case 15:
			printf("Frame relay");
			break;
		case 16:
		case 19:
			printf("Asynchronous Transfer Mode (ATM)");
			break;		
		case 17:
			printf("HDLC");
			break;
		case 18:
			printf("Fibre Channel");
			break;	
		case 20:
			printf("Serial Line");
			break;			
		default:
			printf("Unknown");
			break;
	}
	
	printf(" (%d)", tipo);
}

void imprimirProtocolType(unsigned short tipo)
{
	switch(tipo)
	{
		case 2048:
			printf("IPv4");
			break;
		case 2054:
			printf("ARP");
			break;		
		default:
			printf("Unknown");
			break;
	}
	
	printf(" (%d)", tipo);	
}

void imprimirOpcode(unsigned short tipo)
{
	switch(tipo)
	{
		case 1:
			printf("ARP request");
			break;
		case 2:
			printf("ARP reply");
			break;
		case 3:
			printf("RARP request");
			break;
		case 4:
			printf("RARP reply");
			break;			
		default:
			printf("Unknown");
			break;
	}
	
	printf(" (%d)", tipo);		
}

void imprimirMac(const u_char *pkt_data, int inicio, int fin)
{
	int i = inicio;
	
	for(; i <= fin; i++)
	{
		printf("%02x", pkt_data[i]);
		
		if(i < fin)
			printf(":");
	}	
}

void imprimirIp(const u_char *pkt_data, int inicio, int fin)
{
	int i = inicio;
	
	for(; i <= fin; i++)
	{
		printf("%d", pkt_data[i]);
		
		if(i < fin)
			printf(".");
	}	
}
