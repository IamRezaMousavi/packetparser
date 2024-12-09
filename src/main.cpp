#include <pcap.h>

#include <cstdlib>
#include <cstring>
#include <iostream>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <set>

#include "common.hpp"
#include "db.hpp"
#include "dns.hpp"
#include "tls.hpp"

std::set<std::string> servernames;

void packetHandler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  const struct ether_header *ethHeader = (struct ether_header *)packet;

  switch (ntohs(ethHeader->ether_type)) {
  case ETHERTYPE_IP: {
    const struct ip *ipHeader = (struct ip *)(packet + sizeof(struct ether_header));

    if (ipHeader->ip_p == IPPROTO_TCP) {
      struct tcphdr *tcpHeader = (struct tcphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
      const u_char *tcpData = packet + sizeof(ether_header) + (ipHeader->ip_hl * 4) + (tcpHeader->th_off * 4);
      size_t tcpDataLength = pkthdr->len - (sizeof(ether_header) + (ipHeader->ip_hl * 4) + sizeof(tcphdr));

      // Check for TLS handshake content type (0x16)
      if (tcpDataLength > 0 && tcpData[0] == 0x16) { // 0x16 is the content type for TLS Handshake
        TLS tlsPacket = parseTLS(tcpData);

        TLSPacket packet = {.shost = ether_ntoa((struct ether_addr *)ethHeader->ether_shost),
                            .dhost = ether_ntoa((struct ether_addr *)ethHeader->ether_dhost),
                            .ip_src = inet_ntoa(ipHeader->ip_src),
                            .ip_dst = inet_ntoa(ipHeader->ip_dst),
                            .sport = ntohs(tcpHeader->th_sport),
                            .dport = ntohs(tcpHeader->th_dport),
                            .tls = tlsPacket};

        std::cout << packet << std::endl;
        if (packet.tls.handshake.has_value()) {
          const auto &handshake = packet.tls.handshake.value();
          for (const auto &ext : handshake.extensions) {
            servernames.insert(ext.servername.name);
          }
        }
      }

    } else if (ipHeader->ip_p == IPPROTO_UDP) {
      const struct udphdr *udpHeader = (struct udphdr *)(packet + sizeof(struct ether_header) + (ipHeader->ip_hl * 4));
      const u_char *udpData = packet + sizeof(ether_header) + ipHeader->ip_hl * 4 + sizeof(udphdr);

      if (ntohs(udpHeader->uh_sport) == 53 || ntohs(udpHeader->uh_dport) == 53) {
        DNS packet = parseDNS(udpData);

        DNSPacket dnsPacket = {.shost = ether_ntoa((struct ether_addr *)ethHeader->ether_shost),
                               .dhost = ether_ntoa((struct ether_addr *)ethHeader->ether_dhost),
                               .ip_src = inet_ntoa(ipHeader->ip_src),
                               .ip_dst = inet_ntoa(ipHeader->ip_dst),
                               .sport = ntohs(udpHeader->uh_sport),
                               .dport = ntohs(udpHeader->uh_dport),
                               .dns = packet};

        std::cout << dnsPacket << std::endl;
        for (const auto &q : dnsPacket.dns.queries) {
          servernames.insert(q.name);
        }
      }
    }

    break;
  }

  default:
    break;
  }
}

int main(int argc, char const *argv[]) {
  if (argc < 3 || argc > 4) {
    std::cerr << "Usage " << argv[0] << " <appname> <pacp file> [filter]" << std::endl;
    return EXIT_FAILURE;
  }

  DB db;

  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t *handle;
  struct bpf_program filter;
  char filterExpression[256] = "";

  if (argc == 4) {
    strncpy(filterExpression, argv[3], sizeof(filterExpression) - 1);
  }

  handle = pcap_open_offline(argv[2], errbuf);
  if (handle == nullptr) {
    std::cerr << "Unable to open file: " << errbuf << std::endl;
    return EXIT_FAILURE;
  }

  std::cout << "Reading packets from file: " << argv[2] << std::endl;

  if (strlen(filterExpression) > 0) {
    if (pcap_compile(handle, &filter, filterExpression, 0, PCAP_NETMASK_UNKNOWN) == -1) {
      std::cerr << "Error compiling filter: " << pcap_geterr(handle) << std::endl;
      pcap_close(handle);
      return EXIT_FAILURE;
    }

    if (pcap_setfilter(handle, &filter) == -1) {
      std::cerr << "Error setting filter: " << pcap_geterr(handle) << std::endl;
      pcap_freecode(&filter);
      pcap_close(handle);
      return EXIT_FAILURE;
    }

    std::cout << "Filter applied: " << filterExpression << std::endl;
  }

  pcap_loop(handle, 0, packetHandler, nullptr);

  if (strlen(filterExpression) > 0) {
    pcap_freecode(&filter);
  }
  pcap_close(handle);

  std::cout << "Servernames:" << std::endl;
  for (const auto &servername : servernames) {
    std::cout << servername << std::endl;
  }

  if (!db.insert_servername(argv[1], servernames)) {
    std::cout << "DB Insert Error" << std::endl;
  }

  return EXIT_SUCCESS;
}
