#include "raw_socket.hpp"

#include <cerrno>
#include <cstring>
#include <stdexcept>

// POSIX headers
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>

// Linux packet socket
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <net/ethernet.h>

RawSocket::RawSocket(const std::string &ifname) : fd_(-1), ifindex_(0), ifname_(ifname) {
  fd_ = ::socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
  if (fd_ < 0) {
    throw std::runtime_error(std::string("socket(AF_PACKET) failed: ") + std::strerror(errno));
  }

  ifindex_ = static_cast<int>(if_nametoindex(ifname.c_str()));
  if (ifindex_ == 0) {
    ::close(fd_);
    fd_ = -1;
    throw std::runtime_error("Interface not found: " + ifname);
  }

  sockaddr_ll addr{};
  addr.sll_family   = AF_PACKET;
  addr.sll_protocol = htons(ETH_P_ALL);
  addr.sll_ifindex  = ifindex_;

  if (::bind(fd_, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0) {
    ::close(fd_);
    fd_ = -1;
    throw std::runtime_error(std::string("bind failed: ") + std::strerror(errno));
  }
}

RawSocket::~RawSocket() { close(); }

ssize_t RawSocket::send(std::span<const std::uint8_t> data) {
  ensure_open();

  sockaddr_ll addr{};
  addr.sll_family  = AF_PACKET;
  addr.sll_ifindex = ifindex_;
  addr.sll_halen   = ETH_ALEN;

  ssize_t n = ::sendto(fd_, data.data(), data.size(), 0, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
  if (n < 0) {
    throw std::runtime_error(std::string("sendto failed: ") + std::strerror(errno));
  }
  return n;
}

std::vector<std::uint8_t> RawSocket::recv(std::size_t max_size) {
  ensure_open();

  std::vector<std::uint8_t> buffer(max_size);
  ssize_t                   n = ::recvfrom(fd_, buffer.data(), buffer.size(), 0, nullptr, nullptr);
  if (n < 0) {
    // timeout or interrupt -> no error
    if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
      return {};
    }
    throw std::runtime_error(std::string("recvfrom failed: ") + std::strerror(errno));
  }
  buffer.resize(static_cast<std::size_t>(n));
  return buffer;
}

void RawSocket::set_recv_timeout(int timeout_ms) {
  ensure_open();

  timeval tv{};
  tv.tv_sec  = timeout_ms / 1000;
  tv.tv_usec = (timeout_ms % 1000) * 1000;

  if (::setsockopt(fd_, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0) {
    throw std::runtime_error(std::string("setsockopt(SO_RCVTIMEO) failed: ") + std::strerror(errno));
  }
}

void RawSocket::close() {
  if (fd_ >= 0) {
    ::close(fd_);
    fd_ = -1;
  }
}

void RawSocket::ensure_open() const {
  if (fd_ < 0) {
    throw std::runtime_error("RawSocket is closed");
  }
}

LiveCapture::LiveCapture(const std::string &ifname, int timeout_ms) : socket_(ifname) {
  socket_.set_recv_timeout(timeout_ms);
}

void LiveCapture::set_timeout(int timeout_ms) { socket_.set_recv_timeout(timeout_ms); }

bool LiveCapture::next() {
  while (true) {
    auto pkt = socket_.recv();
    if (pkt.empty())
      continue;
    current_ = RawPacket{std::move(pkt)};
    break;
  }
  return true;
}

const RawPacket &LiveCapture::current() const { return current_; }
