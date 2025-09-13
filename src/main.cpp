#include <pcap.h>

#include <cstdlib>
#include <getopt.h>
#include <iostream>
#include <netinet/ether.h>
#include <unordered_set>

#include "packet.hpp"
#include "pcap.hpp"

std::unordered_set<std::string> servernames;

// DB db;

void packetHandler(u_char *args, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
  (void)args;
  Ether ether(packet, pkthdr->len);

  switch (ether.eth_type) {
  case ETHERTYPE_IP: {
    IP ip(ether.payload(), ether.payloadSize());

    if (ip.protocol == IPPROTO_UDP) {
      UDP udp(ip.payload(), ip.payloadSize());

      if (udp.sport == 53 || udp.dport == 53) {
        DNS dns(udp.payload(), udp.payloadSize());

        Packet pkt = ether / ip / udp / dns;
        std::cout << pkt.toString() << std::endl;

        // db.insert_dns(dnsPacket);

        for (const auto &q : dns.queries) {
          servernames.insert(q.name);
        }
      }
    } else if (ip.protocol == IPPROTO_TCP) {
      TCP tcp(ip.payload(), ip.payloadSize());

      // Check for TLS handshake content type (0x16)
      // 0x16 is the content type for TLS Handshake
      if (tcp.payloadSize() > 0 && tcp.payload()[0] == 0x16) {
        TLS tls(tcp.payload(), tcp.payloadSize());
        if (tls.handshake.has_value()) {
          const auto &handshake = tls.handshake.value();
          if (handshake.type == TLSHandshakeType::TLS_CLIENT_HELLO) {
            Packet pkt = ether / ip / tcp / tls;
            std::cout << pkt.toString() << std::endl;
          }
          for (const auto &ext : handshake.extensions) {
            servernames.insert(ext.servername.name);
          }
        }
      }
    }

    break;
  }

  case ETHERTYPE_IPV6: {
  }

  default:
    break;
  }
}

struct Cli {
  std::string source;
  std::string appname;
  std::optional<std::string> filter;
  bool debug;
} cli;

void usage(const char *progname) {
  std::cerr << "Usage: " << progname << " -s <src> -a <appname> [-f filter] [-d]\n\n"
            << "Options:\n"
            << "  -s <src>        Source (e.g., eth0 or file.pcap)\n"
            << "  -a <appname>    Application name\n"
            << "  -f <filter>     Filter string (Optional)\n"
            << "  -d              Enable debug prints (Optional)\n"
            << "  -h              Show this help message\n";
}

void cli_parser(int argc, char *argv[]) {
  int opt;
  while ((opt = getopt(argc, argv, "m:s:a:f:hd")) != -1) {
    switch (opt) {
    case 's':
      cli.source = optarg;
      break;
    case 'a':
      cli.appname = optarg;
      break;
    case 'f':
      cli.filter = optarg;
      break;
    case 'h':
      usage(argv[0]);
      exit(EXIT_SUCCESS);
    case 'd':
      cli.debug = true;
      break;
    default:
      usage(argv[0]);
      exit(EXIT_FAILURE);
    }
  }

  if (cli.source.empty() || cli.appname.empty()) {
    std::cerr << "Missing required arguments\n\n";
    usage(argv[0]);
    exit(EXIT_FAILURE);
  }
}

int main(int argc, char *argv[]) {
  cli_parser(argc, argv);

  PcapWrapper pcap(cli.source, cli.filter);
  std::cout << "Reading packets from " << cli.source << ": " << cli.appname << std::endl;

  pcap.loop(packetHandler);

  if (!servernames.empty()) {
    std::cout << "Servernames:" << std::endl;
  }

  for (const auto &servername : servernames) {
    std::cout << servername << std::endl;
  }

  return EXIT_SUCCESS;
}
