#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#include <pcap.h>
#include "IP.h"


void packet_handler(u_char *param, const struct pcap_pkthdr *header, const u_char *pkt_data)
{
	struct tm *ltime;
	char timestr[16];
	time_t local_tv_sec;
	int j = 0, k = 0;
	unsigned short tipo = (pkt_data[12] << 8) + pkt_data[13];
	ip_head *ip;
	
	switch (tipo)
	{
		case 2048:
			
			ip = (ip_head *) (pkt_data + 14);
			printf("------------------------------------------T R A M A   I P   E N C O N T R A D A------------------------------------------------------------\n");
			printf("-----------------------------------------------------------------------------------------------------------------------------------------\n");
			printf("-----------------------------------------------------------------------------------------------------------------------------------------\n");
			imprimirTrama(header, pkt_data);
			printf("\n\n");
			analizarIp(ip, pkt_data);
			break;
		case 2054:
			break;
			
		default:
			break;
	}
}


int main()
{
	pcap_if_t *alldevs;
	pcap_if_t *d;
	int inum;
	int i=0;
	pcap_t *adhandle;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	if(pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
		exit(1);
	}
	
	/* Print the list */
	for(d = alldevs; d; d = d -> next)
	{
		printf("%d. %s", ++i, d -> name);
		if (d->description)
			printf(" (%s)\n", d -> description);
		else
			printf(" (No description available)\n");
	}
	
	if(i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}
	
	printf("Enter the interface number (1 - %d): ", i);
	scanf("%d", &inum);
	
	if(inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");
		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}
	
	/* Jump to the selected adapter */
	for(d = alldevs, i = 0; i < inum - 1 ; d = d->next, i++);
	
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
	
	printf("\nlistening on %s...\n", d->description);
	
	/* At this point, we don't need any more the device list. Free it */
	pcap_freealldevs(alldevs);
	
	/* start the capture */
	pcap_loop(adhandle, 100, packet_handler, NULL);
	
	pcap_close(adhandle);
	
	return 0;
}

/* Callback function invoked by libpcap for every incoming packet */


