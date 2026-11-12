#include "pcap.hpp"

#include <stdexcept>

PcapReader::PcapReader(const std::string &filename, const std::optional<std::string> &filter) {
  char errbuf[PCAP_ERRBUF_SIZE]{};
  handle_.reset(pcap_open_offline(filename.c_str(), errbuf));
  if (!handle_)
    throw std::runtime_error(std::string("pcap_open_offline: ") + errbuf);

  if (pcap_datalink(handle_.get()) != DLT_EN10MB)
    throw std::runtime_error("Unsupported link-layer type (expected Ethernet)");

  if (filter)
    set_filter(*filter);
}

bool PcapReader::next() {
  pcap_pkthdr  *header = nullptr;
  const u_char *data   = nullptr;

  int rc;
  do {
    rc = pcap_next_ex(handle_.get(), &header, &data);
  } while (rc == 0);

  if (rc == -2)
    return false; // EOF
  if (rc == -1)
    throw std::runtime_error(std::string("pcap_next_ex: ") + pcap_geterr(handle_.get()));

  current_.data.assign(data, data + header->caplen);
  return true;
}

const RawPacket &PcapReader::current() const { return current_; }

void PcapReader::set_filter(const std::string &filter) {
  bpf_program prog{};
  if (pcap_compile(handle_.get(), &prog, filter.c_str(), 1, PCAP_NETMASK_UNKNOWN) == -1) {
    throw std::runtime_error(std::string("pcap_compile: ") + pcap_geterr(handle_.get()));
  }
  const int rc = pcap_setfilter(handle_.get(), &prog);
  pcap_freecode(&prog);
  if (rc == -1)
    throw std::runtime_error(std::string("pcap_setfilter: ") + pcap_geterr(handle_.get()));
}
