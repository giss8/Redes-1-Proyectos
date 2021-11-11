#include <stdio.h>
#include <stdlib.h>
#include "C:\\Users\\gerik\\OneDrive\\Escritorio\\Include\\pcap\\pcap.h"
#include <pcap.h>
#define LINE_LEN 16
#define RUTA "C:\\Users\\gerik\\OneDrive\\Escritorio\\paquetes3.pcap"
#define 	PCAP_OPENFLAG_PROMISCUOUS   1
#define 	PCAP_SRC_FILE   2
#define 	PCAP_BUF_SIZE   1024

void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);

int main(int argc, char **argv)
{
pcap_t *fp;
char errbuf[PCAP_ERRBUF_SIZE];
char source[PCAP_BUF_SIZE];

   /* if(argc != 2){

        printf("usage: %s filename", argv[0]);
        return -1;

    }*/

    /* Create the source string according to the new WinPcap syntax */
    if ( pcap_createsrcstr( source,         // variable that will keep the source string
                            PCAP_SRC_FILE,  // we want to open a file
                            NULL,           // remote host
                            NULL,           // port on the remote host
                            RUTA, //argv[1],        // name of the file we want to open
                            errbuf          // error buffer
                            ) != 0)
    {
        fprintf(stderr,"\nError creating a source string\n");
        return -1;
    }
    
    /* Open the capture file */
    if ( (fp= (pcap_t *)pcap_open(source,         // name of the device
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

    // read and dispatch packets until EOF is reached
    pcap_loop(fp, 0, dispatcher_handler, NULL);

    return 0;
}



void dispatcher_handler(u_char *temp1, 
                        const struct pcap_pkthdr *header, const u_char *pkt_data)
{
    u_int i=0;

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
    
    printf("\n\n");     
    
	printf("Analisis:\n");
    
	unsigned char longitud = (pkt_data[12]*256)+pkt_data[13];
    printf("Longitud en hexadecimal: %.2x \n",longitud);
    printf("Longitud en decimal: %d \n",longitud);
    
    
    if(longitud<=1500){
    	printf("Es una trama IEEE802.3\n");
    	unsigned char b1 = pkt_data[16]&0x01;
    	unsigned char b2 = (pkt_data[16]>>1)&0x01;
    	    
    	    //printf("%x\n\n",b1);
    	    //printf("%x\n\n",b2);
    	    
    	int nsec = (pkt_data[16]>>1)&0x7f;
	    int nack = (pkt_data[17]>>1)&0x7f;
		int pf1 = (pkt_data[17]>>1)&0x01;
		
    	if(b1==0){
    	    printf("Su mensaje es de tipo I\n");
		    printf("Este es el numero de acuse: %d\n",nack);  
		    printf("Este es el numero de secuencia: %d\n",nsec);
	        
	        
			}
		else if(b1==1 && b2==0){
			printf("Su mensaje es de tipo S\n");
		    printf("Este es el numero de acuse: %d\n",nack);
			
			 
		    
		}else if(b1==1 && b2==1){
			printf("Su mensaje es de tipo U\n");
			
		
		}
		
		printf("%.2x",pkt_data[16]);
	    printf("%.2x\n",pkt_data[17]);
	    
	    
    	if(longitud>3){
    		printf("Se tomaran 2 bits del campo de control (modo extendido)\n"); 
    		
    		if(b1==0){
    			
			   if (pf1==0){
	        	
	        	printf("P/F es 0, entonces esta apagado\n");
	        	
			     }
			   else {
				printf("P/F es 1, entonces esta prendido\n");
			}
        }
 
			if(b1==1 && b2==0)	   {
				
				int codigo = (pkt_data[16]>>2)&0x03;
				
				//printf("%d\n",codigo);

				if (codigo== 0){ //00
					
					printf("Esta listo para recibir\n");
					
				}
				
				else if(codigo== 1){  // 01        
				
				    printf("Esta listo para rechazar\n");
				
				}
				
				else if(codigo== 2){// 10
				
				    printf("Receptor no listo para recibir\n");
				
				}
				
				else if(codigo== 3){// 11
				
				    printf("Rechazo selectivo\n");
				
				}
			if (pf1==0){
	        	
	        	printf("P/F es 0, entonces esta apagado\n");
	        	
			}
			else {
				printf("P/F es 1, entonces esta prendido\n");
				
				}	
			}
			
			else if(b1==1 && b2==1){
			int	codigo1= (pkt_data[16]>>2)&0x03;
			int codigo2= (pkt_data[16]>>5)&0x07;
				
				switch(codigo1){
					
					case 0:  
					       if(codigo2==0){
					       	printf("Comando UI y Respuesta UI (Información sin numerar)\n");
						   }
				           
				           else if(codigo2==1){
					       	printf("Comando SNRM/n");
						   }
				           
				           else if(codigo2==2){
					       	printf("Comando DISC(Desconexion o peticion de desconexion) y Respuesta RD\n");
						   }
						   
						   else if(codigo2==4){
					       	printf("Comando UP(Muestra sin numerar)\n");
						   }
				
				           else if(codigo2==6){
					       	printf("Respuesta UA(Reconocimiento sin numerar)\n");
						   }
				        break;
                    case 2:
                    	   if(codigo2==0){
					       	printf("Comando SIM y Respuesta RIM(Activacion de modo de iniciacion)\n");
						   }
						   
						   else if(codigo2==1){
					       	printf("Comando FRMR y Respuesta FRMR(Rechazo de trama)\n");
						   }
						
						break;
						   
					case 3:  
					       if(codigo2==1){
					       	printf("Comando RSET (Reset)\n");
						   }   
						   
						   else if(codigo2==3){
					       	printf("Comando SNRME(Activacion de modo de respuesta normal ampliada)\n");
						   }
						   
						   else if(codigo2==4){
					       	printf("Comando SABM y Respuesta DM(Activacion de modo respuesta asincrona balanceada)\n");
					       	
						   }
						   
						   else if(codigo2==5){
					       	printf("Comando XID y Respuesta XID(Intercambio de ID)\n");
						   }
						   
						   else if(codigo2==6){
					       	printf("Comando SABME(Activación de modo respuesta asincrona balanceada ampliada)\n");
						   }
						   
						break;
						
					default: 
					         break;
				}
			
			int pf2 = (pkt_data[16]>>4)&0x01;
			
			if (pf2==0){
	        	
	        	printf("P/F es 0, entonces esta apagado\n");
	        	
			}
			else {
				printf("P/F es 1, entonces esta prendido\n");
			}
						
			}
		}
	
		else{
			printf("Se tomara 1 bit del campo de control (modo normal)\n");
			
			int seq2= (pkt_data[16]>>1)&0x07;
			int pf3= (pkt_data[16]>>3)&0x01;
			int ak2= (pkt_data[16]>>4)&0x07;
			
			if(b1==0){
				
			   printf("Este es su numero de secuencia: %d\n",seq2);
			   printf("Este es su numero acuse: %d\n",ak2);
			   
			   if(pf3==0){
			   	printf("Esta P/F apagado: %d\n",pf3);
			   }
			   else{
			   	printf("Esta P/F encendido: %d\n",pf3);
			   }   
			}
			
			else if(b1==1 && b2==0){
			
			int sc= (pkt_data[16]>>2)&0x03;
		    printf("Este es el numero de acuse: %d\n",ak2);
		    printf("Este es el codigo de supervision: %d\n",sc);
		    
		        if(pf3==0){
			   	printf("Esta P/F apagado: %d\n",pf3);
			   }
			   else{
			   	printf("Esta P/F encendido: %d\n",pf3);
			   }   
			}
			
			else if(b1==1 && b2==1){
			
			int ub= (pkt_data[16]>>2)&0x03;
		    printf("Estos son los bits sin numerar: %.2x\n",ak2);
		    printf("Estos son los bits sin numerar: %.2x\n",ub);
		    
		       if(pf3==0){
			   	printf("Esta P/F apagado: %d\n",pf3);
			   }
			   else{
			   	printf("Esta P/F encendido: %d\n",pf3);
			   }   
			}
		}
	
		unsigned char dsap=pkt_data[14]&0x01;
		
		if(dsap==0){
		    printf("Es individual\n");
		}else if(dsap==1){
			printf("Es grupal\n");
		}
		
		unsigned char ssap=pkt_data[15]&0x01;
		if(ssap==0){
			printf("Es comando\n\n");
		}else{
			printf("Es respuesta\n\n");
		}
}
	else if(longitud>1500){
		printf("Es una trama Ethernet\n"); 
	}else{
		printf("Inválido\n");
	}
	
		
}


