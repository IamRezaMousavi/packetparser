#ifndef __PCAP_HPP__
#define __PCAP_HPP__

#include <pcap.h>

#include <optional>
#include <string>

#include "utils.hpp"

class PcapWrapper {
public:
  PcapWrapper(const std::string &source, const std::optional<std::string> &filter = std::nullopt);
  ~PcapWrapper();

  void loop(pcap_handler callback, u_char *user = nullptr);

private:
  pcap_t *handle;
};

#endif /* __PCAP_HPP__ */
