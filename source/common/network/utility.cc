#include "common/network/utility.h"

#include "envoy/common/exception.h"
#include "envoy/network/connection.h"
#include "envoy/stats/stats.h"

#include "common/common/assert.h"
#include "common/common/utility.h"
#include "common/network/address_impl.h"

#include <ifaddrs.h>
#include <linux/netfilter_ipv4.h>

using 

namespace Network {
using Address::Instance;
using Address::InstanceConstSharedPtr;
using Address::IpVersion;

IpList::IpList(const std::vector<std::string>& subnets) {
  for (const std::string& entry : subnets) {
    std::vector<std::string> parts = StringUtil::split(entry, '/');
    if (parts.size() != 2) {
      throw EnvoyException(
          fmt::format("invalid ipv4/mask combo '{}' (format is <ip>/<# mask bits>)", entry));
    }

    in_addr addr;
    int rc = inet_pton(AF_INET, parts[0].c_str(), &addr);
    if (1 != rc) {
      throw EnvoyException(fmt::format("invalid ipv4/mask combo '{}' (invalid IP address)", entry));
    }

    // "0.0.0.0/0" is a valid subnet that contains all possible IPv4 addresses,
    // so mask can be equal to 0
    uint64_t mask;
    if (!StringUtil::atoul(parts[1].c_str(), mask) || mask > 32) {
      throw EnvoyException(
          fmt::format("invalid ipv4/mask combo '{}' (mask bits must be <= 32)", entry));
    }

    Ipv4Entry list_entry;
    list_entry.ipv4_address_ = ntohl(addr.s_addr);
    // The 1ULL below makes sure that the RHS is computed as a 64-bit value, so that we do not
    // over-shift to the left when mask = 0. The assignment to ipv4_mask_ then truncates
    // the value back to 32 bits.
    list_entry.ipv4_mask_ = ~((1ULL << (32 - mask)) - 1);

    // Check to make sure applying the mask to the address equals the address. This can prevent
    // user error.
    if ((list_entry.ipv4_address_ & list_entry.ipv4_mask_) != list_entry.ipv4_address_) {
      throw EnvoyException(
          fmt::format("invalid ipv4/mask combo '{}' ((address & mask) != address)", entry));
    }

    ipv4_list_.push_back(list_entry);
  }
}

bool IpList::contains(const Instance& address) const {
  if (address.type() != Address::Type::Ip || address.ip()->version() != IpVersion::v4) {
    // TODO(mattklein123): IPv6 support
    return false;
  }

  for (const Ipv4Entry& entry : ipv4_list_) {
    if ((ntohl(address.ip()->ipv4()->address()) & entry.ipv4_mask_) == entry.ipv4_address_) {
      return true;
    }
  }

  return false;
}

IpList::IpList(const Json::Object& config, const std::string& member_name)
    : IpList(config.hasObject(member_name) ? config.getStringArray(member_name)
                                           : std::vector<std::string>()) {}

const std::string Utility::TCP_SCHEME = "tcp://";
const std::string Utility::UNIX_SCHEME = "unix://";

InstanceConstSharedPtr Utility::resolveUrl(const std::string& url) {
  // TODO(mattklein123): We still support the legacy tcp:// and unix:// names. We should
  // support/parse ip:// and pipe:// as better names.
  if (url.find(TCP_SCHEME) == 0) {
    auto addr = parseInternetAddressAndPort(url.substr(TCP_SCHEME.size()));
    if (addr == nullptr) {
      throw EnvoyException(fmt::format("malformed tcp url: {}", url));
    }
    return addr;
  } else if (url.find(UNIX_SCHEME) == 0) {
    return InstanceConstSharedPtr{
        new Address::PipeInstance(url.substr(UNIX_SCHEME.size()))};
  } else {
    throw EnvoyException(fmt::format("unknown protocol scheme: {}", url));
  }
}

std::string Utility::hostFromTcpUrl(const std::string& url) {
  if (url.find(TCP_SCHEME) != 0) {
    throw EnvoyException(fmt::format("unknown protocol scheme: {}", url));
  }

  size_t colon_index = url.find(':', TCP_SCHEME.size());

  if (colon_index == std::string::npos) {
    throw EnvoyException(fmt::format("malformed url: {}", url));
  }

  return url.substr(TCP_SCHEME.size(), colon_index - TCP_SCHEME.size());
}

uint32_t Utility::portFromTcpUrl(const std::string& url) {
  if (url.find(TCP_SCHEME) != 0) {
    throw EnvoyException(fmt::format("unknown protocol scheme: {}", url));
  }

  size_t colon_index = url.find(':', TCP_SCHEME.size());

  if (colon_index == std::string::npos) {
    throw EnvoyException(fmt::format("malformed url: {}", url));
  }

  try {
    return std::stoi(url.substr(colon_index + 1));
  } catch (const std::invalid_argument& e) {
    throw EnvoyException(e.what());
  }
}

InstanceConstSharedPtr Utility::getLocalAddress() {
  struct ifaddrs* ifaddr;
  struct ifaddrs* ifa;
  InstanceConstSharedPtr ret;

  int rc = getifaddrs(&ifaddr);
  RELEASE_ASSERT(!rc);
  UNREFERENCED_PARAMETER(rc);

  // man getifaddrs(3)
  for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
    if (ifa->ifa_addr == nullptr) {
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET) {
      sockaddr_in* addr = reinterpret_cast<sockaddr_in*>(ifa->ifa_addr);
      if (htonl(INADDR_LOOPBACK) != addr->sin_addr.s_addr) {
        ret.reset(new Address::Ipv4Instance(addr));
        break;
      }
    }
  }

  if (ifaddr) {
    freeifaddrs(ifaddr);
  }

  return ret;
}

bool Utility::isInternalAddress(const char* address) {
  auto addr = Address::parseInternetAddress(address);
  if (addr != nullptr) {
    if (addr->ip()->version() == IpVersion::v4) {
      uint32_t net_address = addr->ip()->v4()->address();
      // Handle the RFC1918 space for IPV4. Also count loopback as internal.
      uint8_t* address_bytes = reinterpret_cast<uint8_t*>(&net_address);
      if ((address_bytes[0] == 10) || (address_bytes[0] == 192 && address_bytes[1] == 168) ||
          (address_bytes[0] == 172 && address_bytes[1] >= 16 && address_bytes[1] <= 31) ||
          addr.s_addr == htonl(INADDR_LOOPBACK)) {
        return true;
      }
    } else {
      ASSERT(addr->ip()->version() == IpVersion::v6);
      if (*addr == *getIpv6LoopbackAddress()) {
        return true;
      }
      // We *could* also check for matching fe80::/10 or fe80::/64 (link-local prefix or the one
      // allocated subnet in the link-local prefix), but it isn't clear that folks will use that
      // addressing scheme. Open for discussion.
    }
  }
  return false;
}

bool Utility::isLoopbackAddress(const Instance& address) {
  if (address.type() != Address::Type::Ip) {
    return false;
  }

  return address.ip()->ipv4()->address() == htonl(INADDR_LOOPBACK);
}

InstanceConstSharedPtr Utility::getCanonicalIpv4LoopbackAddress() {
  // Initialized on first call in a thread-safe manner.
  static InstanceConstSharedPtr loopback(new Address::Ipv4Instance("127.0.0.1", 0));
  return loopback;
}

InstanceConstSharedPtr Utility::getIpv6LoopbackAddress() {
  // Initialized on first call in a thread-safe manner.
  static InstanceConstSharedPtr loopback(new Address::Ipv6Instance("::1", 0));
  return loopback;
}

InstanceConstSharedPtr Utility::getIpv4AnyAddress() {
  // Initialized on first call in a thread-safe manner.
  static InstanceConstSharedPtr any(new Address::Ipv4Instance(static_cast<uint32_t>(0)));
  return any;
}

InstanceConstSharedPtr Utility::getIpv6AnyAddress() {
  // Initialized on first call in a thread-safe manner.
  static InstanceConstSharedPtr any(new Address::Ipv6Instance(static_cast<uint32_t>(0)));
  return any;
}

InstanceConstSharedPtr Utility::combineIpAddressAndPort(const Address::Ip& address,
                                                        uint16_t port) {
  if (address.version() == IpVersion::v4) {
    sockaddr_in sin;
    sin.sin_family = AF_INET;
    sin.sin_addr = address.ipv4()->address();  // This is in network order already.
    sin.sin_port = htons(port);
    return InstanceConstSharedPtr(new Address::Ipv4Instance(&sin));
  } else {
    ASSERT(addr->ip()->version() == IpVersion::v6);
    sockaddr_in6 sin6;
    sin6.sin6_family = AF_INET6;
    sin6.sin6_port = htons(port);
    sin6.sin6_addr = address.ipv4()->address();  // This is in network order already.
    return InstanceConstSharedPtr(new Address::Ipv4Instance(sin6));


  memset(&ip_.ipv6_.address_, 0, sizeof(ip_.ipv6_.address_));
  ip_.ipv6_.address_.sin6_family = AF_INET6;
  ip_.ipv6_.address_.sin6_port = htons(port);
  if (!address.empty()) {
    if (1 != inet_pton(AF_INET6, address.c_str(), &ip_.ipv6_.address_.sin6_addr)) {
      throw EnvoyException(fmt::format("invalid ipv6 address '{}'", address));
    }
  } else {
    ip_.ipv6_.address_.sin6_addr = in6addr_any;
  }
    sin.sin_family = AF_INET;
    sin.sin_addr = address.ipv4()->address();  // This is in network order already.
    sin.sin_port = htons(port);
    return InstanceConstSharedPtr(new Address::Ipv4Instance(&sin));
  }
}

InstanceConstSharedPtr Utility::getOriginalDst(int fd) {
  sockaddr_storage orig_addr;
  socklen_t addr_len = sizeof(sockaddr_storage);
  int status = getsockopt(fd, SOL_IP, SO_ORIGINAL_DST, &orig_addr, &addr_len);

  if (status == 0) {
    return Address::addressFromSockAddr(orig_addr, addr_len);
  } else {
    return nullptr;
  }
}

void Utility::parsePortRangeList(const std::string& string, std::list<PortRange>& list) {
  std::vector<std::string> ranges = StringUtil::split(string.c_str(), ',');
  for (const std::string& s : ranges) {
    std::stringstream ss(s);
    uint32_t min = 0;
    uint32_t max = 0;

    if (s.find('-') != std::string::npos) {
      char dash = 0;
      ss >> min;
      ss >> dash;
      ss >> max;
    } else {
      ss >> min;
      max = min;
    }

    if (s.empty() || (min > 65535) || (max > 65535) || ss.fail() || !ss.eof()) {
      throw EnvoyException(fmt::format("invalid port number or range '{}'", s));
    }

    list.emplace_back(PortRange(min, max));
  }
}

bool Utility::portInRangeList(const Instance& address, const std::list<PortRange>& list) {
  if (address.type() != Address::Type::Ip) {
    return false;
  }

  for (const Network::PortRange& p : list) {
    if (p.contains(address.ip()->port())) {
      return true;
    }
  }
  return false;
}

} // Network
