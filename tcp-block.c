#include "./tcp-block.h"

void usage() {
	printf("tcp-block <interface> <pattern>\n");
	printf("tcp-block wlan0 \"Host: test.gilgil.net\"\n");
}

typedef struct {
	char* dev_;
	char *pattern;
} Param;

Param param = {
	.dev_ = NULL,
	.pattern = NULL
};


bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	param->pattern = argv[2];
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	char my_mac[0x1000] = {0, };
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	get_my_mac(param.dev_, my_mac, sizeof(my_mac));

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}


		if(is_ipv4_http_packet(packet)) {
			filter_http(pcap, packet, header->len, param.pattern, my_mac);
		} else {
		//	printf("[!] It is not IPv4-TCP!\n");
		}
	}

	pcap_close(pcap);
}

