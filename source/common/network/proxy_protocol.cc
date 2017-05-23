#include "common/network/proxy_protocol.h"

#include "envoy/common/exception.h"
#include "envoy/event/dispatcher.h"
#include "envoy/event/file_event.h"
#include "envoy/stats/stats.h"

#include "common/common/empty_string.h"
#include "common/network/address_impl.h"
#include "common/network/listener_impl.h"
#include "common/network/utility.h"

namespace Network {

const std::string ProxyProtocol::ActiveConnection::PROXY_TCP4 = "PROXY TCP4 ";
const std::string ProxyProtocol::ActiveConnection::PROXY_TCP6 = "PROXY TCP6 ";

ProxyProtocol::ProxyProtocol(Stats::Scope& scope)
    : stats_{ALL_PROXY_PROTOCOL_STATS(POOL_COUNTER(scope))} {}

void ProxyProtocol::newConnection(Event::Dispatcher& dispatcher, int fd, ListenerImpl& listener) {
  std::unique_ptr<ActiveConnection> p{new ActiveConnection(*this, dispatcher, fd, listener)};
  p->moveIntoList(std::move(p), connections_);
}

ProxyProtocol::ActiveConnection::ActiveConnection(ProxyProtocol& parent,
                                                  Event::Dispatcher& dispatcher, int fd,
                                                  ListenerImpl& listener)
    : parent_(parent), fd_(fd), listener_(listener), search_index_(1) {
  file_event_ = dispatcher.createFileEvent(fd, [this](uint32_t events) {
    ASSERT(events == Event::FileReadyType::Read);
    UNREFERENCED_PARAMETER(events);
    onRead();
  }, Event::FileTriggerType::Edge, Event::FileReadyType::Read);
}

ProxyProtocol::ActiveConnection::~ActiveConnection() {
  if (fd_ != -1) {
    ::close(fd_);
  }
}

void ProxyProtocol::ActiveConnection::onRead() {
  try {
    onReadWorker();
  } catch (const EnvoyException& ee) {
    parent_.stats_.downstream_cx_proxy_proto_error_.inc();
    close();
  }
}

void ProxyProtocol::ActiveConnection::onReadWorker() {
  std::string proxy_line;
  if (!readLine(fd_, proxy_line)) {
    return;
  }

  auto line_parts = StringUtil::splitKeep(proxy_line, " ");
  uint64_t src_port, dst_port;
  if (line_parts.size() == 6 && line_parts[0] == "PROXY" &&
      StringUtil::atoul(line_parts[4], &src_port) &&
      StringUtil::atoul(line_parts[5], &dst_port)) {
    Network::Address::InstanceConstSharedPtr src_addr =
        Network::Address::parseInternetAddress(line_parts[2]);
    Network::Address::InstanceConstSharedPtr dst_addr =
        Network::Address::parseInternetAddress(line_parts[3]);
    if (src_addr != nullptr && dst_addr != nullptr && ) {
      auto src_version = src_addr->ip()->version();
      auto dst_version = dst_addr->ip()->version();
      // TODO(jamessynge): It might be useful to have a utility function for "setting"
      // the port in an address (i.e. creating a new Address::Instance with a different port).
      if (src_version != dst_version) {
        ;  // Broken input.
      } else if (line_parts[1] == "TCP4" && src_version == Network::Address::IpVersion::v4) {
        

      }
          dst_version == Network::Address::IpVersion::v4


          (line_parts[1] == "TCP6" && version == Network::Address::IpVersion::v6)) {

    }

  }

) {
    Network::Address::InstanceConstSharedPtr source_addr =
        Network::Address::parseInternetAddress(line_parts[2]);
    if (source_addr != nullptr) {
      auto version = source_addr->ip()->version();
      // TODO(jamessynge): It might be useful to have a utility function for "setting"
      // the port in an address (i.e. creating a new Address::Instance with a different port).
      if ((line_parts[1] == "TCP4" && version == Network::Address::IpVersion::v4))
          (line_parts[1] == "TCP6" && version == Network::Address::IpVersion::v6)) {
        
        

  ListenerImpl& listener = listener_;
  int fd = fd_;
  fd_ = -1;

  removeFromList(parent_.connections_);

  // TODO(mattklein123): Parse the remote port instead of passing zero.
  // TODO(mattklein123): IPv6 support.
  listener.newConnection(fd, 
                         Network::Address::InstanceConstSharedPtr{
                             new Network::Address::Ipv4Instance(remote_address, 0)},
                         listener_.socket().localAddress());

    throw EnvoyException("failed to read proxy protocol");
  }

  uint64_t source_port
  if (!StringUtil::atoul(line_parts[4], &source_port)) {
    throw EnvoyException("failed to read proxy protocol");
  }

  Network::Address::InstanceConstSharedPtr source_addr =
      Network::Address::parseInternetAddress(line_parts[2]);
  if (source_addr

  if (line_parts[1] == "TCP4" && source) {
    
    is_tcp4 = true;
    
  } else if (line_parts[1] == "TCP6") {
    is_tcp6 = true;
  } else {
    throw EnvoyException("failed to read proxy protocol");
  }



uint64_t& out, int base = 10);
  if (proxy_line.find(PROXY_TCP4) != 0) {
    throw EnvoyException("failed to read proxy protocol");
  }

  size_t index = proxy_line.find(" ", PROXY_TCP4.size());
  if (index == std::string::npos) {
    throw EnvoyException("failed to read proxy protocol");
  }

  size_t addr_len = index - PROXY_TCP4.size();
  std::string remote_address = proxy_line.substr(PROXY_TCP4.size(), addr_len);

  ListenerImpl& listener = listener_;
  int fd = fd_;
  fd_ = -1;

  removeFromList(parent_.connections_);

  // TODO(mattklein123): Parse the remote port instead of passing zero.
  // TODO(mattklein123): IPv6 support.
  listener.newConnection(fd,
                         Network::Address::InstanceConstSharedPtr{
                             new Network::Address::Ipv4Instance(remote_address, 0)},
                         listener.socket().localAddress());
}

void ProxyProtocol::ActiveConnection::close() {
  ::close(fd_);
  fd_ = -1;
  removeFromList(parent_.connections_);
}

bool ProxyProtocol::ActiveConnection::readLine(int fd, std::string& s) {
  while (buf_off_ < MAX_PROXY_PROTO_LEN) {
    ssize_t nread = recv(fd, buf_ + buf_off_, MAX_PROXY_PROTO_LEN - buf_off_, MSG_PEEK);

    if (nread == -1 && errno == EAGAIN) {
      return false;
    } else if (nread < 1) {
      throw EnvoyException("failed to read proxy protocol");
    }

    bool found = false;
    // continue searching buf_ from where we left off
    for (; search_index_ < buf_off_ + nread; search_index_++) {
      if (buf_[search_index_] == '\n' && buf_[search_index_ - 1] == '\r') {
        search_index_++;
        found = true;
        break;
      }
    }

    nread = recv(fd, buf_ + buf_off_, search_index_ - buf_off_, 0);

    if (nread < 1) {
      throw EnvoyException("failed to read proxy protocol");
    }

    buf_off_ += nread;

    if (found) {
      s.assign(buf_, buf_off_);
      return true;
    }
  }

  throw EnvoyException("failed to read proxy protocol");
}

} // Network
