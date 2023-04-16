#include "argparse/argparse.hpp"
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pcap.h>
#include <stdio.h>
#include <string.h>

/*TODO
pridat toto do dokumentace, spolu s MIT licenci samotnou(v doc na ni muze byt jenom odkaz ale musi byt includnuta s projektem)
"This software uses the argparse library, which is licensed under the MIT license. The argparse library is Copyright (c) 2017-2022 Parthasarathi Ranganathan."
*/

pcap_t *handle;
int linkhdrlen;
int packets;

void list_interfaces() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *interface_list;
    if (pcap_findalldevs(&interface_list, errbuf) == PCAP_ERROR) {
        std::cerr << "Error finding interfaces: " << errbuf << std::endl;
        exit(1);
    }

    for (pcap_if_t *i = interface_list; i != nullptr; i = i->next) {
        std::cout << i->name << std::endl;
    }
    pcap_freealldevs(interface_list);
    exit(0);
}

void packet_handler(u_char *user, const struct pcap_pkthdr *packethdr, const u_char *packetptr) {
    struct ip *iphdr;
    struct icmp *icmphdr;
    struct tcphdr *tcphdr;
    struct udphdr *udphdr;
    char iphdrInfo[256];
    char srcip[256];
    char dstip[256];

    // Skip the datalink layer header and get the IP header fields.
    packetptr += linkhdrlen;
    iphdr = (struct ip *)packetptr;
    strcpy(srcip, inet_ntoa(iphdr->ip_src));
    strcpy(dstip, inet_ntoa(iphdr->ip_dst));
    sprintf(iphdrInfo, "ID:%d TOS:0x%x, TTL:%d IpLen:%d DgLen:%d",
            ntohs(iphdr->ip_id), iphdr->ip_tos, iphdr->ip_ttl,
            4 * iphdr->ip_hl, ntohs(iphdr->ip_len));

    // Advance to the transport layer header then parse and display
    // the fields based on the type of hearder: tcp, udp or icmp.
    printf("inside of loop.\n");
    packetptr += 4 * iphdr->ip_hl;
    switch (iphdr->ip_p) {
        case IPPROTO_TCP:
            tcphdr = (struct tcphdr *)packetptr;
            printf("TCP  %s:%d -> %s:%d\n", srcip, ntohs(tcphdr->th_sport),
                   dstip, ntohs(tcphdr->th_dport));
            printf("%s\n", iphdrInfo);
            printf("%c%c%c%c%c%c Seq: 0x%x Ack: 0x%x Win: 0x%x TcpLen: %d\n",
                   (tcphdr->th_flags & TH_URG ? 'U' : '*'),
                   (tcphdr->th_flags & TH_ACK ? 'A' : '*'),
                   (tcphdr->th_flags & TH_PUSH ? 'P' : '*'),
                   (tcphdr->th_flags & TH_RST ? 'R' : '*'),
                   (tcphdr->th_flags & TH_SYN ? 'S' : '*'),
                   (tcphdr->th_flags & TH_SYN ? 'F' : '*'),
                   ntohl(tcphdr->th_seq), ntohl(tcphdr->th_ack),
                   ntohs(tcphdr->th_win), 4 * tcphdr->th_off);
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break;

        case IPPROTO_UDP:
            udphdr = (struct udphdr *)packetptr;
            printf("UDP  %s:%d -> %s:%d\n", srcip, ntohs(udphdr->uh_sport),
                   dstip, ntohs(udphdr->uh_dport));
            printf("%s\n", iphdrInfo);
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break;

        case IPPROTO_ICMP:
            icmphdr = (struct icmp *)packetptr;
            printf("ICMP %s -> %s\n", srcip, dstip);
            printf("%s\n", iphdrInfo);
            printf("Type:%d Code:%d ID:%d Seq:%d\n", icmphdr->icmp_type, icmphdr->icmp_code,
                   ntohs(icmphdr->icmp_hun.ih_idseq.icd_id), ntohs(icmphdr->icmp_hun.ih_idseq.icd_seq));
            printf("+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+\n\n");
            packets += 1;
            break;
    }
}

int main(int argc, char *argv[]) {
    argparse::ArgumentParser parser("ipk-sniffer");
    parser.add_description("IPK project 2: ZETA - network sniffer.");

    // If this parameter is not specified (and any other parameters as well), or if only -i/--interface is specified
    // without a value (and any other parameters are unspecified), a list of active interfaces is printed.
    parser.add_argument("-i", "--interface")
        .implicit_value(true)
        .help("Network interface to listen on");
    try {
        parser.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        // this is the only way (known to me) how to implement behaviour described above
        parser.add_argument("-i", "--interface")
            .required()
            .help("Network interface to listen on");

        parser.add_argument("-p")
            .default_value(-1)
            .help("Port to listen on")
            .action([](const std::string &value) { return std::stoi(value); });

        parser.add_argument("-t", "--tcp")
            .default_value(false)
            .implicit_value(true)
            .help("Capture TCP packets");

        parser.add_argument("-u", "--udp")
            .default_value(false)
            .implicit_value(true)
            .help("Capture UDP packets");

        parser.add_argument("--arp")
            .default_value(false)
            .implicit_value(true)
            .help("Capture ARP packets");

        parser.add_argument("--icmp4")
            .default_value(false)
            .implicit_value(true)
            .help("Capture ICMPv4 packets");

        parser.add_argument("--icmp6")
            .default_value(false)
            .implicit_value(true)
            .help("Capture ICMPv6 packets");

        parser.add_argument("--ndp")
            .default_value(false)
            .implicit_value(true)
            .help("Capture ICMPv6 NDP packets");

        parser.add_argument("--igmp")
            .default_value(false)
            .implicit_value(true)
            .help("Capture IGMP packets");

        parser.add_argument("--mld")
            .default_value(false)
            .implicit_value(true)
            .help("Capture MLD packets");

        parser.add_argument("-n")
            .default_value(1)
            .help("Number of packets to capture")
            .action([](const std::string &value) { return std::stoi(value); });
        try {
            parser.parse_args(argc, argv);
        } catch (const std::runtime_error &err) {
            std::cerr << err.what() << std::endl;
            std::cerr << parser;
            return 1;
        }
    }
    if (parser.is_used("--interface")) {
        if (argc == 2) {
            list_interfaces();
        }
    } else {
        list_interfaces();
    }
    std::string interface = parser.get<std::string>("--interface");
    bool tcp = parser.get<bool>("--tcp");
    bool udp = parser.get<bool>("--udp");
    int port = parser.get<int>("-p");
    bool icmp4 = parser.get<bool>("--icmp4");
    bool icmp6 = parser.get<bool>("--icmp6");
    bool arp = parser.get<bool>("--arp");
    bool ndp = parser.get<bool>("--ndp");
    bool igmp = parser.get<bool>("--igmp");
    bool mld = parser.get<bool>("--mld");
    int num = parser.get<int>("-n");

    if (!(tcp || udp || icmp4 || icmp6 || arp || ndp || igmp || mld)) {
        tcp = udp = icmp4 = icmp6 = arp = ndp = igmp = mld = true;
    }
    if (port >= 0 && !(udp || tcp)) {
        std::cerr << "port can be used only in combination with tcp or udp!" << std::endl;
        exit(1);
    }

    char errbuf[PCAP_ERRBUF_SIZE];
    // Create packet capture handle.
    handle = pcap_open_live(interface.c_str(), BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "handle couldn't be created!" << std::endl;
        exit(1);
    }
    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "only ethernet is supported!" << std::endl;
        exit(1);
    }
    // set filter
    bpf_u_int32 mask;
    bpf_u_int32 net;
    if (pcap_lookupnet(interface.c_str(), &net, &mask, errbuf) == -1) { // returns ipv4 network number and network mask
        std::cerr << "cannot get netmask" << std::endl;
        mask = 0;
        net = 0;
    }
    char filter_exp[2048] = {
        0,
    }; // Default filter is empty (no filtering)
    std::string to_filter = "";
    // Check if -t or --tcp is specified
    if (tcp) {
        to_filter.append("tcp "); // Add TCP filter expression
        if (port >= 0) {
            to_filter.append("port ");
            to_filter.append(std::to_string(port));
            to_filter.append(" ");
        }
    }

    // Check if -u or --udp is specified
    if (udp) {
        if (tcp)
            to_filter.append(" or "); // Add OR operator if necessary
        to_filter.append("udp ");     // Add UDP filter expression
        if (port >= 0) {
            to_filter.append("port ");
            to_filter.append(std::to_string(port));
            to_filter.append(" ");
        }
    }

    // Check for other filters
    if (icmp4) {
        if (to_filter.empty()) {
            to_filter.append("icmp ");
        } else {
            to_filter.append("or icmp ");
        }
    }
    if (icmp6) {
        if (to_filter.empty()) {
            to_filter.append("icmp6 ");
        } else {
            to_filter.append("or icmp6 ");
        }
    }
    if (arp) {
        if (to_filter.empty()) {
            to_filter.append("arp ");
        } else {
            to_filter.append("or arp ");
        }
    }
    if (ndp && !icmp6) {
        if (to_filter.empty()) {
            to_filter.append("icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137) ");
        } else {
            to_filter.append("or (icmp6 and (icmp6[0] == 133 or icmp6[0] == 134 or icmp6[0] == 135 or icmp6[0] == 136 or icmp6[0] == 137)) ");
        }
    }
    if (igmp) {
        if (to_filter.empty()) {
            to_filter.append("igmp ");
        } else {
            to_filter.append("or igmp ");
        }
    }
    if (mld && !icmp6) {
        if (to_filter.empty()) {
            to_filter.append("icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132) ");
        } else {
            to_filter.append("or (icmp6 and (icmp6[0] == 130 or icmp6[0] == 131 or icmp6[0] == 132)) ");
        }
    }

    // Compile and set filter
    bpf_program fp;
    if (pcap_compile(handle, &fp, to_filter.c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
        fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_exp, pcap_geterr(handle));
        return 1;
    }
    if (pcap_setfilter(handle, &fp) == -1) {
        std::cerr << "cannot install filter!" << std::endl;
        return (1);
    }

    // Start the packet capture with a set count or continually if the count is 0.
    if (pcap_loop(handle, num, packet_handler, (u_char *)NULL) < 0) {
        fprintf(stderr, "pcap_loop failed: %s\n", pcap_geterr(handle));
        return -1;
    }
    pcap_close(handle);
    printf("DONE!\n");
    return 0;
}
