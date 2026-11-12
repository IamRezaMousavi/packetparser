#ifndef PCAP_READER_HPP
#define PCAP_READER_HPP

#include <pcap/pcap.h>

#include <memory>
#include <optional>
#include <string>

#include "packet_source.hpp"

class PcapReader : public PacketSource {
public:
  explicit PcapReader(const std::string &filename, const std::optional<std::string> &filter = std::nullopt);

protected:
  bool             next() override;
  const RawPacket &current() const override;

private:
  struct PcapDeleter {
    void operator()(pcap_t *h) const noexcept {
      if (h)
        pcap_close(h);
    }
  };

  std::unique_ptr<pcap_t, PcapDeleter> handle_;
  RawPacket                            current_;

  void set_filter(const std::string &filter);
};

#endif
