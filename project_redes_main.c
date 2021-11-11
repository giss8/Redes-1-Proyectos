#include <stdio.h>
#include <stdlib.h>
#include <winsock2.h>
#include<windows.h>
#include <math.h>
#include "C:\\Users\\gerik\\OneDrive\\Escritorio\\Include\\pcap.h"
#ifdef _MSC_VER
#define _CRT_SECURE_NO_WARNINGS
#endif
#define LINE_LEN 16
//#include <pcap.h>
#include <string.h>
#include "ARPTrama.h"
#include "LLCTrama.h"
#include "IPTrama.h"
#include "ICMPTrama.h"
#include "IGMPTrama.h"
#include "TCPTrama.h"
#include "UDPTrama.h"
#define RUTA_IEEE "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\LLC.pcap"
#define RUTA_IP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\IP.pcap"
#define RUTA_ARP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\ARP.pcap"
#define RUTA_ICMP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\ICMP.pcap"
#define RUTA_IGMP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\IGMP2.pcap"
#define RUTA_TCP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\TCP.pcap"
#define RUTA_UDP "C:\\Users\\gerik\\OneDrive\\Escritorio\\UNIVERSIDAD\\ESCOM\\CUARTO SEMESTRE\\REDES I\\SEGUNDO PARCIAL\\Project_redes\\UDP.pcap"
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024


int main(){
	char *Resp = malloc(20);
	do{
		pcap_if_t *alldevs;
		pcap_if_t *d;
		pcap_t *fp;
		char errbuf[PCAP_ERRBUF_SIZE];
		char source[PCAP_BUF_SIZE];
		int inum=0,i=0;
		int captura_tramas;
		int Tipo_Protocolo;
		pcap_t *adhandle;
	
		system("cls");
		printf("\t-*-*-*-*-*-*-*P R O T O C O L---A N A L Y Z E R*-*-*-*-*-*-*-\nElija una opcion para capturar las tramas\n 1. Tramas al vuelo\n 2. Por archivo\nTeclee la opcion a elegir (1-2): ");
		scanf("%d",&captura_tramas);
		while(captura_tramas!=1 && captura_tramas!=2){
			printf("Seleccione una opcion existente.\n Opcion: ");
			scanf("%d",&captura_tramas);
		}
		system("cls");
		printf("SELECCIONA EL PROTOCOLO A ANALIZAR\n 1. LLC\n 2. ARP\n 3. IP\n 4. ICMP\n 5. IGMP\n 6. TCP\n 7. UDP\n");
		printf("teclee la opcion a elegir: ");
		scanf("%d",&Tipo_Protocolo);
		while(Tipo_Protocolo<1 && Tipo_Protocolo>8){
			printf("Seleccione una opción existente.\n");
			scanf("%d",&Tipo_Protocolo);
		}
		
		switch(captura_tramas){
			
			case 1:{
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
										 5000,			// read timeout
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
	
				break;
			}
			case 2:{
				switch(Tipo_Protocolo){
					case 1:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_IEEE, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
			    {
			        fprintf(stderr,"\nError creating a source string\n");
			        return -1;
			    }
						break;
					}
					case 2:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_ARP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
			    {
			        fprintf(stderr,"\nError creating a source string\n");
			        return -1;
			    }
						break;
					}
					case 3:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_IP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
			    {
			        fprintf(stderr,"\nError creating a source string\n");
			        return -1;
			    }
						break;
					}
					case 4:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_ICMP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
			    {
			        fprintf(stderr,"\nError creating a source string\n");
			        return -1;
			    }
						break;
					}
					case 5:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_IGMP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
						    {
						        fprintf(stderr,"\nError creating a source string\n");
						        return -1;
						    }
						break;
					}
					case 6:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_TCP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
					    {
					        fprintf(stderr,"\nError creating a source string\n");
					        return -1;
					    }
						break;
					}
					case 7:{
						if ( pcap_createsrcstr( source,         // variable that will keep the source string
			                            PCAP_SRC_FILE,  // we want to open a file
			                            NULL,           // remote host
			                            NULL,           // port on the remote host
			                            RUTA_UDP, //argv[1],        // name of the file we want to open
			                            errbuf          // error buffer
			                            ) != 0)
			    {
			        fprintf(stderr,"\nError creating a source string\n");
			        return -1;
			    }
						break;
					}
				}
				if ( (adhandle= (pcap_t *)pcap_open(source,         // name of the device
	                        65536,          // portion of the packet to capture
	                                        // 65536 guarantees that the whole packet will be captured on all the link layers
	                         PCAP_OPENFLAG_PROMISCUOUS,     // promiscuous mode
	                         1000,              // read timeout
	                         NULL,              // authentication on the remote machine
	                         errbuf         // error buffer
	                         ) ) == NULL)
			    {
			        fprintf(stderr,"\nUnable to open the file %s\n", source);
			        return -1;
			    }
					break;
			}
			
		}
		
		if(Tipo_Protocolo==1){
			pcap_loop(adhandle, 15, IEEE_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==2){
			pcap_loop(adhandle, 15, ARP_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==3){
			pcap_loop(adhandle, 15, IP_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==4){
			pcap_loop(adhandle, 15, ICMP_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==5){
			pcap_loop(adhandle,41, IGMP_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==6){
			pcap_loop(adhandle, 15, TCP_Trama, NULL);
			pcap_close(adhandle);
		}
		if(Tipo_Protocolo==7){
			pcap_loop(adhandle, 15, UDP_Trama, NULL);
			pcap_close(adhandle);
		}
		printf("\n"); 
	printf("-------------------------------------------------------------------------------------------------------------------\n\n"); 
		puts("Desea hacer otra consulta: ");
		scanf("%s",Resp);
	}while(strcmp(Resp,"si")==0 || strcmp(Resp,"")==0 || strcmp(Resp,"si")==0);
	
	puts("Vuelva pronto");
	
	return 0;
}


