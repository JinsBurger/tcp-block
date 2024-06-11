#include "./pcap-test.h"

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

uint32_t is_http_pkt(char *data, uint32_t data_len) {
	const char* http_methods[] = {"GET", "POST", "HEAD", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH"};

	for(int i=0; i < sizeof(http_methods) / sizeof(char*); i++) {
		if(data_len > strlen(http_methods[i]) && !strncasecmp(data, http_methods[i], strlen(http_methods[i]))) {		
			return 0;
		}		
	}
	return -1;
}

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}


		if(is_ipv4_tcp_packet(packet) == SUCCESS) {
			dump_ipv4_tcp_packet(packet, header->caplen);
		} else {
		//	printf("[!] It is not IPv4-TCP!\n");
		}

		//printf("%u bytes captured\n", header->caplen);
	}

	pcap_close(pcap);
}

