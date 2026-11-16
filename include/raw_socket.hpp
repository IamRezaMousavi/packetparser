#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "packet_source.hpp"

class FileDescriptor {
public:
  FileDescriptor() noexcept = default;
  explicit FileDescriptor(int fd) noexcept : fd_(fd) {}

  // Non-copyable
  FileDescriptor(const FileDescriptor &)            = delete;
  FileDescriptor &operator=(const FileDescriptor &) = delete;

  // Movable
  FileDescriptor(FileDescriptor &&other) noexcept;
  FileDescriptor &operator=(FileDescriptor &&other) noexcept;

  ~FileDescriptor();

  [[nodiscard]] int get() const noexcept {
    return fd_;
  }

  FileDescriptor &operator=(int new_fd) noexcept;

  void reset(int new_fd = -1) noexcept;

  [[nodiscard]] int release() noexcept;

  [[nodiscard]] bool valid() const noexcept {
    return fd_ >= 0;
  }

  [[nodiscard]] explicit operator bool() const noexcept {
    return valid();
  }

private:
  int fd_ = -1;
};

class RawSocket {
public:
  explicit RawSocket(const std::string &ifname);

  // Non-copyable
  RawSocket(const RawSocket &)            = delete;
  RawSocket &operator=(const RawSocket &) = delete;

  // Movable
  RawSocket(RawSocket &&other)            = default;
  RawSocket &operator=(RawSocket &&other) = default;

  ~RawSocket() = default;

  ssize_t                   send(std::span<const std::uint8_t> data);
  std::vector<std::uint8_t> recv(std::size_t max_size = 65536);

  void set_recv_timeout(int timeout_ms);

  int fd() const {
    return fd_.get();
  }
  int ifindex() const {
    return ifindex_;
  }
  const std::string &ifname() const {
    return ifname_;
  }
  bool is_open() const {
    return fd_.valid();
  }

private:
  void ensure_open() const;

  FileDescriptor fd_;
  int            ifindex_;
  std::string    ifname_;
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
