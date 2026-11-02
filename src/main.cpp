#include <getopt.h>

#include <atomic>
#include <csignal>
#include <cstdlib>
#include <iostream>
#include <span>
#include <unordered_set>

#include "db.hpp"
#include "packet.hpp"
#include "raw_socket.hpp"

std::unordered_set<std::string> servernames;

DBConfig     config;
DBConnection db(config);

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
        std::cout << pkt.toString() << std::endl;

        db.insert_dns(pkt);

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
            std::cout << pkt.toString() << std::endl;

            db.insert_tls(pkt);
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
  std::string                source;
  std::string                appname;
  std::optional<std::string> filter;
  bool                       debug;
} cli;

void usage(const char *progname) {
  std::cerr << "Usage: " << progname << " -s <src> -a <appname> [-f filter] [-d]\n\n"
            << "Options:\n"
            << "  -s <src>        Interface name (e.g., eth0)\n"
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

std::atomic<bool> running{true};

void on_signal(int) { running = false; }

int main(int argc, char *argv[]) {
  cli_parser(argc, argv);
  db.setAppname(cli.appname);

  std::cout << "Reading packets from " << cli.source << ": " << cli.appname << std::endl;

  try {
    RawSocket sock(cli.source);
    sock.set_recv_timeout(1000);
    std::cout << "Opened raw socket on " << sock.ifname() << " (ifindex=" << sock.ifindex() << ")\n";

    std::signal(SIGINT, on_signal);
    std::cout << "Listening... (Ctrl+C to stop)\n\n";

    while (running) {
      auto data = sock.recv();
      if (data.empty())
        continue; // timeout or interrupt

      try {
        packetParser(data);
      } catch (const std::exception &e) {
        std::cerr << "Error Parser: " << e.what() << "\n";
      }
    }

    std::cout << "\nStopped.\n";

  } catch (const std::exception &e) {
    std::cerr << "Error: " << e.what() << "\n";
    return 1;
  }

  if (!servernames.empty()) {
    std::cout << "Servernames:" << std::endl;
  }

  for (const auto &servername : servernames) {
    std::cout << servername << std::endl;
  }

  return EXIT_SUCCESS;
}
