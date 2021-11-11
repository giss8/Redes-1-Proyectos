#define LINE_LEN 50

/* 4 bytes IP address */
typedef struct ip_add
{
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
} ip_add;

/* IPv4 header */
typedef struct ip_head
{
	u_char ver_ihl; // Version (4 bits) + IP header length (4 bits)
	u_char tos; // Type of service
	u_short tlen; // Total length
	u_short identification; // Identification
	u_short flags_fo; // Flags (3 bits) + Fragment offset (13 bits)
	u_char ttl; // Time to live
	u_char proto; // Protocol
	u_short crc; // Header checksum
	ip_add saddr; // Source address
	ip_add daddr; // Destination address
	u_int op_pad; // Option + Padding
} ip_head;

/* UCP header*/
typedef struct udp_head
{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_short len; // length
	u_short crc; // Checksum
} udp_head;

/* TCP header*/
typedef struct tcp_head
{
	u_short sport; // Source port
	u_short dport; // Destination port
	u_int sec_num; // secuence number
	u_int ack_num; // ack number
	u_char d_offset_rsv; // 4bit data offset +4bit reserved
	u_char flags; // TCP flags
	u_short window; // window
	u_short crc; // Checksum
	u_short upointer; // urgent pointer
} tcp_head;

/* ICMP header*/
typedef struct icmp_head
{
	u_char type; // ICMP type
	u_char code; // ICMP code
	u_short crc; // Checksum
} icmp_head;

void convertirNumeroBinario(u_char numero, u_char cantidad_bits)
{
	int corrimiento = 0;
	
	for(corrimiento = cantidad_bits - 1; corrimiento >= 0; corrimiento--)
		printf("%u", (numero >> corrimiento) & 0x01);

}

u_short invertir_bytes(u_short numero)
{
	return ((numero & 0xff) << 8) + (numero >> 8);
}

void imprimirSelectorClase(u_char tos)
{
	u_char tipo = (tos >> 5) & 0x3;
	
	convertirNumeroBinario(tipo, 3);
	
	switch(tipo)
	{
    	case 0:
        	printf(" Routine (default)\n");
        	break;
    	case 1:
        	printf(" Priority (Trafico de datos)\n");
        	break;
    	case 2:
        	printf(" Immediate (Trafico de datos)\n"); 
        	break;
    	case 3:
        	printf(" Flash (Call Signaling)\n");
        	break;
    	case 4:
        	printf(" Flash Override (Vcon., streaming)\n");
        	break;
    	case 5:
        	printf(" CRITIC/ECP (Voz)\n");
        	break;
    	case 6:
        	printf(" Internetwork Control (Trafico de control)\n");
        	break;
    	case 7:
        	printf(" Network Control (Trafico de control)\n");
        	break;
        default:
        	break;
	}
}

void imprimirECN(u_char tos)
{
	int tipo = tos & 0x3;
	
	convertirNumeroBinario(tipo, 2);

	switch(tipo)
	{
		case 0:
        	printf(" Sin capacidad ECN\n");
        	break;
    	case 1:
        	printf(" Capacidad de transporte ECN (0)\n");
        	break;
    	case 2:
        	printf(" Capacidad de transporte ECN (1)\n"); 
        	break;
    	case 3:
        	printf(" Congestion encontrada\n");
        	break;
	}
}

void imprimirFlags(u_short flags)
{
	u_char tipo = (flags >> 13) & 0x3;

	convertirNumeroBinario(tipo, 3);
	
	switch(tipo)
	{
		case 0:
			printf(" Last fragment");
		case 1:
        	printf(" More fragments");
        	break;
    	case 2:
        	printf(" Don't fragment");
        	break;
	}
	
	printf("\n");
}

void imprimirIP(ip_add ip)
{
	printf("%u.%u.%u.%u\n", ip.byte1, ip.byte2, ip.byte3, ip.byte4);
}

void analizarUDP(udp_head *udp)
{
	printf("-->Source port: %02X\n", invertir_bytes(udp -> sport));
	printf("-->Destination port: %02X\n", invertir_bytes(udp -> dport));
	printf("-->Length: %u\n", invertir_bytes(udp -> len));
	printf("-->Checksum: %02X\n", invertir_bytes(udp -> crc));
}

void imprimirFlagTCP(u_char flag)
{
	if (flag & 1)
		printf(" FIN");
	if (flag & 2)
		printf(" SYN");
	if (flag & 4)
		printf(" RST");
	if (flag & 8)
		printf(" PSH");
	if (flag & 16)
		printf(" ACK");
	if (flag & 32)
		printf(" URG");
	if (flag & 64)
		printf(" ECE");
	if (flag & 128)
		printf(" CWR");	
	printf("\n");
}

void analizarTCP(tcp_head *tcp)
{
	printf("-->Source port: %02X\n", invertir_bytes(tcp -> sport));
	printf("-->Destination port: %02X\n", invertir_bytes(tcp -> dport));
	printf("-->Secuence number: %u\n", tcp -> sec_num);
	printf("-->Ack number: %u\n", tcp -> ack_num);
	printf("-->Offset: %u\n", (tcp -> d_offset_rsv) >> 4);
	printf("-->Reserved: %u\n", (tcp -> d_offset_rsv) & 0x0f);
	printf("-->Flags: ");
	convertirNumeroBinario(tcp -> flags, 8);
	imprimirFlagTCP(tcp -> flags);
	printf("-->Windows size: %u\n", invertir_bytes(tcp -> window));
	printf("-->Checksum: %02X\n", invertir_bytes(tcp -> crc));
	printf("-->Urgent pointer: %02X\n", invertir_bytes(tcp -> upointer));
}

imprimirTipo(u_char tipo)
{	
	switch(tipo)
	{
		case 0:
			printf("Echo Reply (0)\n");
			break;
		case 3:
			printf("Destination Unreachable (3)\n");
			break;
		case 5:
			printf("Redirect Message (5)\n");
			break;
		case 8:
			printf("Echo Request (8)\n");
			break;
		case 9:
			printf("Router Advertisement (9)\n");
			break;
		case 10:
			printf("Router Solicitation (10)\n");
			break;
		case 11:
			printf("Time Exceeded (11)\n");
			break;
		case 12:
			printf("Parameter Problem (12)\n");
			break;
		case 13:
			printf("Timestamp (13)\n");
			break;
		case 14:
			printf("Timestamp Reply (14)\n");
			break;
	}
}

void codigoEchoReply(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Echo Reply (0)\n");
			break;
	}
}

void codigoEchoRequest(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Echo request (0)\n");
			break;
	}
}

void codigoDestUn(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Destination network unreachable (0)\n");
			break;
		case 1:
			printf("Destination host unreachable (1)\n");
			break;
		case 2:
			printf("Destination protocol unreachable (2)\n");
			break;
		case 3:
			printf("Destination protocol port (3)\n");
			break;
		case 4:
			printf("Fragmentation needed and DF flag set (4)\n");
			break;
		case 5:
			printf("Source route failed (5)\n");
			break;
	}
}

void codigoRedMes(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Redirect datagram for the network (0)\n");
			break;
		case 1:
			printf("Redirect datagram for the host (1)\n");
			break;
		case 2:
			printf("Redirect datagram for the type of service and network (2)\n");
			break;
		case 3:
			printf("Redirect datagram for the service and host (3)\n");
			break;
	}
}

void codigoRouterAdv_Sol(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Use to discover the addresses of operational routers (0)\n");
			break;
	}
}

void codigoTimeEx(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Time to live exceeded in transit (0)\n");
			break;
		case 1:
			printf("Fragment reassembly time exceeded (1)\n");
			break;
	}	
}

void codigoParPro(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Pointer indicates error (0)\n");
			break;
		case 1:
			printf("Missing required option (1)\n");
			break;
		case 2:
			printf("Bad length (2)\n");
			break;
	}
}

void codigoTimestamp(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Used for time synchronization (0)\n");
			break;
	}
}

void codigoTimestampRep(u_char codigo)
{
	switch(codigo)
	{
		case 0:
			printf("Reply to timestamp message (0)\n");
			break;
	}
}

void imprimirCodigo(u_char tipo, u_char codigo)
{	
	switch(tipo)
	{
		case 0:
			codigoEchoReply(codigo);
			break;
		case 3:
			codigoDestUn(codigo);
			break;
		case 5:
			codigoRedMes(codigo);
			break;
		case 8:
			codigoEchoRequest(codigo);
			break;
		case 9:
			codigoRouterAdv_Sol(codigo);
			break;
		case 10:
			codigoRouterAdv_Sol(codigo);
			break;
		case 11:
			codigoTimeEx(codigo);
			break;
		case 12:
			codigoParPro(codigo);
			break;
		case 13:
			codigoTimestamp(codigo);
			break;
		case 14:
			codigoTimestampRep(codigo);
			break;
	}
}

void analizarICMP(icmp_head *icmp)
{
	printf("-->Tipo: ");
	imprimirTipo(icmp -> type);
	printf("-->Codigo: ");
	imprimirCodigo(icmp -> type, icmp -> code);
	printf("-->Cheksum: %04X\n", invertir_bytes(icmp -> crc));
}

void analizarProtocolo(u_char protocolo, const u_char *pkt_data, u_char ihl)
{
	switch (protocolo)
	{
		case 1:
			printf("---> ICMP (1)\n");
			analizarICMP((icmp_head *) (pkt_data + 14 + ihl));
			break;
		case 6:
			printf(" TCP (6)\n");
			analizarTCP((tcp_head *) (pkt_data + 14 + ihl));
			break;
		case 17:
			printf(" UDP (17)\n");
			analizarUDP((udp_head *) (pkt_data + 14 + ihl));
			break;
	}
}

void analizarIp(ip_head *ip, const u_char *pkt_data)
{
	u_short flas_flo_i = invertir_bytes(ip -> flags_fo);
	u_char version = (ip -> ver_ihl) >> 4;
	u_char ihl = ((ip -> ver_ihl) & 15) * 4;
	
	printf("Version: %u\n", version);
	printf("IP Header Length: %d bytes (%u)\n", ihl, ((ip -> ver_ihl) & 15));
	printf("Class selector: ");
	imprimirSelectorClase(ip -> tos);
	printf("ECN: ");
	imprimirECN(ip -> tos);
	printf("Total length: %u\n", invertir_bytes(ip -> tlen));
	printf("Identification: %u\n", invertir_bytes(ip -> identification));
	printf("Flags: ");
	imprimirFlags(flas_flo_i);
	printf("Fragment offset: %u\n", flas_flo_i & 8191);
	printf("TTL: %u\n", ip -> ttl);
	
	printf("Protocolo:");
	analizarProtocolo(ip -> proto, pkt_data, ihl);
	
	printf("Checksum: %02X\n", invertir_bytes(ip -> crc));
	printf("Source IP address: ");
	imprimirIP(ip -> saddr);
	printf("Destination IP address: ");
	imprimirIP(ip -> daddr);
	printf("Options: %u\n\n", ip -> op_pad);
	
	if(ip -> proto == 1)
		system("pause");
	
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


