#include <getopt.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <memory>
#include <span>
#include <unordered_set>

#include "db.hpp"
#include "packet.hpp"
#include "pcap.hpp"
#include "raw_socket.hpp"

std::unordered_set<std::string> servernames;
std::shared_ptr<DBConnection>   db = nullptr;

void packetParser(std::span<const uint8_t> p) {
  size_t pos = 0;
  Ether  ether(p);
  pos += ether.size();

  switch (ether.eth_type) {
  case ETHERTYPE_IP: {
    IP ip(p.subspan(pos));
    pos += ip.size();

    if (ip.protocol == IPPROTO_UDP) {
      UDP udp(p.subspan(pos));
      pos += udp.size();

      if (udp.sport == 53 || udp.dport == 53) {
        DNS dns(p.subspan(pos));

        Packet pkt = ether / ip / udp / dns;
        std::cout << pkt.toString();

        db->insert_dns(pkt);

        for (const auto &q : dns.queries) {
          servernames.insert(q.name);
        }
      }
    } else if (ip.protocol == IPPROTO_TCP) {
      TCP tcp(p.subspan(pos));
      pos += tcp.size();

      // Check for TLS handshake content type (0x16)
      // 0x16 is the content type for TLS Handshake
      if (p.size() > pos && p[pos] == 0x16) {
        TLS tls(p.subspan(pos));
        if (tls.handshake.has_value()) {
          const auto &handshake = tls.handshake.value();
          if (handshake.type == TLSHandshakeType::ClientHello) {
            Packet pkt = ether / ip / tcp / tls;
            std::cout << pkt.toString();

            db->insert_tls(pkt);
          }

          for (const auto &ext : handshake.extensions) {
            if (ext.servername.has_value())
              servernames.insert(ext.servername.value().name);
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
  std::string                interface;
  std::string                pcap_file;
  std::string                appname;
  std::optional<std::string> filter;
  bool                       debug;
} cli;

void usage(const char *progname) {
  std::cerr << "Usage: " << progname << " -i <interface> | -p <pcap_file> -a <appname> [-f filter] [-d]\n\n"
            << "Options:\n"
            << "  -i <interface>  Interface name (e.g., eth0)\n"
            << "  -p <pcap_file>  Pcap file name (e.g., packets.pcap)\n"
            << "  -a <appname>    Application name\n"
            << "  -f <filter>     Filter string (Optional)\n"
            << "  -d              Enable debug prints (Optional)\n"
            << "  -h              Show this help message\n";
}

void cli_parser(int argc, char *argv[]) {
  int opt;
  while ((opt = getopt(argc, argv, "i:p:a:f:hd")) != -1) {
    switch (opt) {
    case 'i':
      cli.interface = optarg;
      break;
    case 'p':
      cli.pcap_file = optarg;
      break;
    case 'a':
      cli.appname = optarg;
      break;
    case 'f':
      cli.filter = optarg;
      break;
    case 'd':
      cli.debug = true;
      break;
    case 'h':
    default:
      usage(argv[0]);
      std::exit(EXIT_FAILURE);
    }
  }

  if ((cli.interface.empty() && cli.pcap_file.empty()) || cli.appname.empty()) {
    std::cerr << "Missing required arguments\n\n";
    usage(argv[0]);
    std::exit(EXIT_FAILURE);
  }

  if (!cli.interface.empty() && !cli.pcap_file.empty()) {
    std::cerr << "Cannot specify both -i and -p\n\n";
    usage(argv[0]);
    std::exit(EXIT_FAILURE);
  }
}

std::atomic<bool> running{true};

void on_signal(int) { running = false; }

int main(int argc, char *argv[]) {
  cli_parser(argc, argv);

  const std::string source = cli.interface.empty() ? cli.pcap_file : cli.interface;
  std::cout << "Reading packets from " << source << " (" << cli.appname << ")\n";

  std::signal(SIGINT, on_signal);

  try {
    DBConfig dbconfig;
    db = std::make_shared<DBConnection>(dbconfig);
    db->setAppname(cli.appname);

    std::unique_ptr<PacketSource> source_ptr;
    if (!cli.interface.empty()) {
      auto live  = std::make_unique<LiveCapture>(cli.interface);
      source_ptr = std::move(live);
      std::cout << "Listening... (Ctrl+C to stop)\n\n";
    } else {
      source_ptr = std::make_unique<PcapReader>(cli.pcap_file, cli.filter);
    }

    for (const auto &pkt : *source_ptr) {
      if (!running)
        break;

      try {
        packetParser(pkt.bytes());
      } catch (const std::exception &e) {
        std::cerr << "Error Parser: " << e.what() << '\n';
      }
    }

    std::cout << "Done.\n";

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return EXIT_FAILURE;
  }

  if (!servernames.empty()) {
    std::cout << "Servernames:" << std::endl;
  }

  for (const auto &servername : servernames) {
    std::cout << servername << std::endl;
  }

  return EXIT_SUCCESS;
}
