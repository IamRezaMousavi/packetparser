#include "pcap.hpp"

PcapWrapper::PcapWrapper(const std::string &source, const std::optional<std::string> &filter) {
  char errbuf[PCAP_ERRBUF_SIZE];
  if (source.size() >= 5 && source.substr(source.size() - 5) == ".pcap") {
    handle = pcap_open_offline(source.c_str(), errbuf);
  } else {
    handle = pcap_open_live(source.c_str(), 65536, 1, 0, errbuf);
  }

  if (handle == nullptr) {
    panic("Unable to open " + source + ": " + std::string(errbuf));
  }

  // std::cout << "Reading packets from " << source << std::endl;

  if (filter.has_value()) {
    struct bpf_program filter_s;
    if (pcap_compile(handle, &filter_s, filter.value().c_str(), 0, PCAP_NETMASK_UNKNOWN) == -1) {
      pcap_close(handle);
      panic("Error compiling filter: " + std::string(pcap_geterr(handle)));
    }

    if (pcap_setfilter(handle, &filter_s) == -1) {
      pcap_freecode(&filter_s);
      pcap_close(handle);
      panic("Error setting filter: " + std::string(pcap_geterr(handle)));
    }

    // std::cout << "Filter applied: " << filter.value() << std::endl;
  }
}

PcapWrapper::~PcapWrapper() { pcap_close(handle); }

void PcapWrapper::loop(pcap_handler callback, u_char *userdata) {
  if (pcap_loop(handle, 0, callback, userdata) == -1) {
    panic("Error in packet loop: " + std::string(pcap_geterr(handle)));
  }
}
