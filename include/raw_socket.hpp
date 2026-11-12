#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "packet_source.hpp"

class RawSocket {
public:
  explicit RawSocket(const std::string &ifname);

  // Non-copyable, movable (TODO)
  RawSocket(const RawSocket &)            = delete;
  RawSocket &operator=(const RawSocket &) = delete;
  RawSocket(RawSocket &&other)            = delete;
  RawSocket &operator=(RawSocket &&other) = delete;

  ~RawSocket();

  ssize_t                   send(std::span<const std::uint8_t> data);
  std::vector<std::uint8_t> recv(std::size_t max_size = 65536);

  void set_recv_timeout(int timeout_ms);

  int                fd() const { return fd_; }
  int                ifindex() const { return ifindex_; }
  const std::string &ifname() const { return ifname_; }
  bool               is_open() const { return fd_ >= 0; }

  void close();

private:
  void ensure_open() const;

  int         fd_;
  int         ifindex_;
  std::string ifname_;
};

class LiveCapture : public PacketSource {
public:
  explicit LiveCapture(const std::string &ifname, int timeout_ms = 1000);

  void set_timeout(int timeout_ms);

protected:
  bool             next() override;
  const RawPacket &current() const override;

private:
  RawSocket socket_;
  RawPacket current_;
};
