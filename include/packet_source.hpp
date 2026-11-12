#pragma once

#include <cstdint>
#include <iterator>
#include <memory>
#include <optional>
#include <span>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

struct RawPacket {
  std::vector<std::uint8_t> data;

  std::span<const std::uint8_t> bytes() const noexcept { return data; }
  explicit                      operator std::span<const std::uint8_t>() const noexcept { return data; }
};

class PacketSource {
public:
  class Iterator {
  public:
    using iterator_concept  = std::input_iterator_tag;
    using iterator_category = std::input_iterator_tag;
    using value_type        = RawPacket;
    using difference_type   = std::ptrdiff_t;
    using reference         = const RawPacket &;

    Iterator() = default;

    const RawPacket &operator*() const { return *current_; }

    Iterator &operator++() {
      if (source_ && !source_->next()) {
        source_ = nullptr;
        current_.reset();
      } else if (source_) {
        current_ = std::make_shared<RawPacket>(source_->current());
      }
      return *this;
    }

    void operator++(int) { ++*this; }

    friend bool operator==(const Iterator &a, const Iterator &b) noexcept { return a.source_ == b.source_; }

  private:
    friend class PacketSource;

    explicit Iterator(PacketSource *src) : source_(src) {
      if (source_ && source_->next()) {
        current_ = std::make_shared<RawPacket>(source_->current());
      } else {
        source_ = nullptr;
      }
    }

    PacketSource              *source_ = nullptr;
    std::shared_ptr<RawPacket> current_;
  };

  virtual ~PacketSource() = default;

  Iterator begin() { return Iterator{this}; }
  Iterator end() const noexcept { return {}; }

protected:
  virtual bool             next()          = 0;
  virtual const RawPacket &current() const = 0;
};
