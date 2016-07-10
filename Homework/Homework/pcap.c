/*
* Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
* Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)
* All rights reserved.
*
* Redistribution and use in source and binary forms, with or without
* modification, are permitted provided that the following conditions
* are met:
*
* 1. Redistributions of source code must retain the above copyright
* notice, this list of conditions and the following disclaimer.
* 2. Redistributions in binary form must reproduce the above copyright
* notice, this list of conditions and the following disclaimer in the
* documentation and/or other materials provided with the distribution.
* 3. Neither the name of the Politecnico di Torino, CACE Technologies
* nor the names of its contributors may be used to endorse or promote
* products derived from this software without specific prior written
* permission.
*
* THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
* "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
* LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
* A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
* OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
* SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
* LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
* DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
* THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
* (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
* OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
*
*/

#ifdef _MSC_VER
/*
* we do not want the warnings about the old deprecated and unsecure CRT functions
* since these examples can be compiled under *nix as well
*/
#define _CRT_SECURE_NO_WARNINGS
#endif

#include <stdlib.h>
#include <stdio.h>

#include <pcap.h>
#include <WinSock2.h>

#pragma comment (lib, "ws2_32.lib")  

#define LINE_LEN 16
#define FILTER "tcp && ip"
#pragma warning(disable:4996)

struct heth {
	u_char dmac[6];
	u_char smac[6];
	u_char type[2];
};

struct hipaddr {
	u_long sip;
	u_long dip;
};

struct hport {
	u_short sport;
	u_short dport;
};

int main(int argc, char **argv)
{
	pcap_if_t *alldevs, *d;
	pcap_t *fp;
	u_int inum, i = 0;
	char errbuf[PCAP_ERRBUF_SIZE];
	int res;
	struct pcap_pkthdr *header;
	const u_char *pkt_data;
	bpf_u_int32 NetMask;
	struct bpf_program fcode;
	struct heth het;
	struct hipaddr hip;
	int len = 0;
	struct sockaddr_in addr_s, addr_d;
	struct hport hprt;

	if (argc < 3)
	{
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
			printf("%d. %s\n    ", ++i, d->name);

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
		if ((fp = pcap_open_live(d->name,	// name of the device
			65536,							// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
		)) == NULL)
		{
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		}
	}
	else
	{
		/* Do not check for the switch type ('-s') */
		if ((fp = pcap_open_live(argv[2],	// name of the device
			65536,							// portion of the packet to capture. 
											// 65536 grants that the whole packet will be captured on all the MACs.
			1,								// promiscuous mode (nonzero means promiscuous)
			1000,							// read timeout
			errbuf							// error buffer
		)) == NULL)
		{
			fprintf(stderr, "\nError opening adapter\n");
			return -1;
		}
	}

	if (FILTER != NULL)
	{
		// We should loop through the adapters returned by the pcap_findalldevs_ex()
		// in order to locate the correct one.
		//
		// Let's do things simpler: we suppose to be in a C class network ;-)
		NetMask = 0xffffff;

		//compile the filter
		if (pcap_compile(fp, &fcode, FILTER, 1, NetMask) < 0)
		{
			fprintf(stderr, "\nError compiling filter: wrong syntax.\n");

			pcap_close(fp);
			return -3;
		}

		//set the filter
		if (pcap_setfilter(fp, &fcode)<0)
		{
			fprintf(stderr, "\nError setting the filter\n");

			pcap_close(fp);
			return -4;
		}

	}

	printf("\nlistening on %s...\n", d->description);

	/* Read the packets */
	while ((res = pcap_next_ex(fp, &header, &pkt_data)) >= 0)
	{

		if (res == 0)
			/* Timeout elapsed */
			continue;

		/* print pkt timestamp and pkt len */
		// printf("%ld:%ld (%ld)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
		printf("\n=======================================================\n=======================================================\n\n");

		len = 0;
		memcpy(&het, pkt_data, 14);
		len += 14;
		memcpy(&hip, &(pkt_data[len + 12]), 8);

		// tcp 헤더의 port 출력을 위해 len 변수에 ethernet 헤더 길이 + ip 헤더 길이(유동적이기때문..) 저장
		len += (pkt_data[14] & 15) * 4;
		memcpy(&hprt, &(pkt_data[len]), 4);

		/* Print the packet */
		for (i = 1; (i < header->caplen + 1); i++)
		{
			printf("%.2x ", pkt_data[i - 1]);
			if ((i % LINE_LEN) == 0) printf("\n");
		}
		printf("\n\n");

		// 목적지 mac 주소 출력
		printf("Destination MAC : ");
		for (i = 0; i<6; i++)
			printf("%.2x ", het.dmac[i]);

		// 출발지 mac 주소 출력
		printf("\nSource MAC : ");
		for (i = 0; i<6; i++)
			printf("%.2x ", het.smac[i]);

		printf("\n\n");

		memcpy(&addr_s.sin_addr.S_un, &hip.sip, 4);
		memcpy(&addr_d.sin_addr.S_un, &hip.dip, 4);

		// 출발지 ip 주소 출력
		printf("Source IP : ");
		printf("%s ", inet_ntoa(addr_s.sin_addr));

		// 목적지 ip 주소 출력
		printf("\nDestination IP : ");
		printf("%s ", inet_ntoa(addr_d.sin_addr));

		printf("\n\n");

		// 출발지 port 출력
		printf("Source PORT : ");
		printf("%d", ntohs(hprt.sport));

		// 목적지 port 출력
		printf("\nDestination PORT : ");
		printf("%d", ntohs(hprt.dport));

		printf("\n=======================================================\n=======================================================\n\n");
	}

	if (res == -1)
	{
		printf("Error reading the packets: %s\n", pcap_geterr(fp));
		return -1;
	}

	pcap_close(fp);
	return 0;
}
