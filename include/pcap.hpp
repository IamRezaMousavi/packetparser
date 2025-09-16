#ifndef __PCAP_HPP__
#define __PCAP_HPP__

#include <pcap.h>

#include <optional>
#include <string>

#include "utils.hpp"

/**
 * A wrapper to pcap handler.
 *
 * This is a wrapper to simple handle pcap lib features.
 */
class PcapWrapper {
public:
  /**
   * @param source pcap filename or interface name.
   * @param filter packet filter string. this param is optional to not capture all packets.
   */
  PcapWrapper(const std::string &source, const std::optional<std::string> &filter = std::nullopt);

  ~PcapWrapper();

  /**
   * Run a loop on packets to handle with callback function.
   * @param callback handler function.
   * @param user optional pointer to data to pass in handler function.
   */
  void loop(pcap_handler callback, u_char *user = nullptr);

private:
  pcap_t *handle;
};

#endif /* __PCAP_HPP__ */
