#include <arpa/inet.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <signal.h>
#include <sys/socket.h>
#include <unistd.h>

#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <iostream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <utility>
#include <vector>

namespace {

constexpr std::uint16_t default_port = 4242;
constexpr std::uint32_t default_distance = 1200;
constexpr std::uint8_t trep_version = 1;
constexpr std::uint8_t trep_route_protocol = 100;
constexpr int reconnect_seconds = 2;
constexpr int connect_timeout_ms = 5000;
constexpr int io_timeout_seconds = 5;
constexpr int tcp_user_timeout_ms = 10000;
constexpr int netlink_timeout_seconds = 5;
constexpr int netlink_dump_attempts = 3;
constexpr int debounce_ms = 250;

volatile sig_atomic_t stop_requested = 0;
bool debug_logging = false;
bool quiet_logging = false;

template <typename... Args>
void log_info(Args&&... args) {
    if (quiet_logging) return;
    (std::cerr << ... << std::forward<Args>(args)) << "\n";
}

template <typename... Args>
void log_debug(Args&&... args) {
    if (quiet_logging or not debug_logging) return;
    (std::cerr << ... << std::forward<Args>(args)) << "\n";
}

void on_signal(int) {
    stop_requested = 1;
}

[[noreturn]] void fail_errno(const std::string& what) {
    throw std::runtime_error(
        what + ": " + std::strerror(errno));
}

struct Address {
    int family = AF_UNSPEC;
    in_addr ipv4 {};
    in6_addr ipv6 {};
};

struct Prefix4 {
    std::uint32_t network_be = 0;
    std::uint8_t length = 0;
};

struct Prefix6 {
    in6_addr network {};
    std::uint8_t length = 0;
};

struct ExportPolicy4 {
    std::vector<Prefix4> filters;
    std::vector<Prefix4> exact_routes;
    std::vector<Prefix4> export_filters;
    std::vector<Prefix4> import_filters;

    bool export_connected = false;
    bool export_static = false;
    bool export_default = false;
};

struct ExportPolicy6 {
    std::vector<Prefix6> filters;
    std::vector<Prefix6> exact_routes;
    std::vector<Prefix6> export_filters;
    std::vector<Prefix6> import_filters;

    bool export_connected = false;
    bool export_static = false;
    bool export_default = false;
};

enum class MessageType : std::uint8_t {
    hello = 1,
    sync_begin = 2,
    route4 = 3,
    route6 = 4,
    sync_end = 5,
};

#pragma pack(push, 1)

struct WireHeader {
    char magic[4];
    std::uint8_t version;
    std::uint8_t type;
    std::uint16_t payload_length_be;
};

struct WireRoute4 {
    std::uint8_t prefix_length;
    std::uint8_t reserved[3];
    std::uint32_t network_be;
};

struct WireRoute6 {
    std::uint8_t prefix_length;
    std::uint8_t reserved[3];
    in6_addr network;
};

#pragma pack(pop)

static_assert(sizeof(WireHeader) == 8);
static_assert(sizeof(WireRoute4) == 8);
static_assert(sizeof(WireRoute6) == 20);

std::uint32_t prefix_mask4(std::uint8_t length) {
    if (length == 0) {
        return 0;
    }

    return htonl(0xffffffffU << (32U - length));
}

void mask_prefix6(in6_addr& address, std::uint8_t length) {
    for (unsigned byte = 0; byte < 16; ++byte) {
        const unsigned bit_offset = byte * 8;

        if (length >= bit_offset + 8) {
            continue;
        }

        if (length <= bit_offset) {
            address.s6_addr[byte] = 0;
            continue;
        }

        const unsigned keep_bits = length - bit_offset;
        const auto mask = static_cast<std::uint8_t>(
            0xffU << (8U - keep_bits));

        address.s6_addr[byte] &= mask;
    }
}

Address parse_address(const std::string& text) {
    Address address;

    if (::inet_pton(AF_INET, text.c_str(), &address.ipv4) == 1) {
        address.family = AF_INET;
        return address;
    }

    if (::inet_pton(AF_INET6, text.c_str(), &address.ipv6) == 1) {
        address.family = AF_INET6;
        return address;
    }

    throw std::runtime_error("invalid address: " + text);
}

std::uint64_t parse_unsigned(
    const std::string& text,
    std::uint64_t maximum,
    const std::string& what) {

    if (
        text.empty() or
        text.find_first_not_of("0123456789") != std::string::npos) {

        throw std::runtime_error("bad " + what + ": " + text);
    }

    std::uint64_t value = 0;

    try {
        value = std::stoull(text);
    } catch (const std::exception&) {
        throw std::runtime_error("bad " + what + ": " + text);
    }

    if (value > maximum) {
        throw std::runtime_error("bad " + what + ": " + text);
    }

    return value;
}

std::string address_to_string(const Address& address) {
    char buffer[INET6_ADDRSTRLEN] {};

    const void* data =
        address.family == AF_INET
            ? static_cast<const void*>(&address.ipv4)
            : static_cast<const void*>(&address.ipv6);

    if (::inet_ntop(
            address.family,
            data,
            buffer,
            sizeof(buffer)) == nullptr) {

        return "?";
    }

    return buffer;
}

std::string ipv4_to_string(std::uint32_t address_be) {
    in_addr address {};
    address.s_addr = address_be;

    char buffer[INET_ADDRSTRLEN] {};

    if (::inet_ntop(
            AF_INET,
            &address,
            buffer,
            sizeof(buffer)) == nullptr) {

        return "?";
    }

    return buffer;
}

std::string ipv6_to_string(const in6_addr& address) {
    char buffer[INET6_ADDRSTRLEN] {};

    if (::inet_ntop(
            AF_INET6,
            &address,
            buffer,
            sizeof(buffer)) == nullptr) {

        return "?";
    }

    return buffer;
}

int compare_addresses(const Address& left, const Address& right) {
    if (left.family != right.family) {
        throw std::runtime_error("local/peer family mismatch");
    }

    if (left.family == AF_INET) {
        const std::uint32_t left_value = ntohl(left.ipv4.s_addr);
        const std::uint32_t right_value = ntohl(right.ipv4.s_addr);

        if (left_value < right_value) {
            return -1;
        }

        if (left_value > right_value) {
            return 1;
        }

        return 0;
    }

    return std::memcmp(
        &left.ipv6,
        &right.ipv6,
        sizeof(in6_addr));
}

Prefix4 parse_prefix4(const std::string& text) {
    const auto slash = text.find('/');

    if (slash == std::string::npos) {
        throw std::runtime_error("prefix needs /len: " + text);
    }

    in_addr address {};

    if (::inet_pton(
            AF_INET,
            text.substr(0, slash).c_str(),
            &address) != 1) {

        throw std::runtime_error("bad IPv4 prefix: " + text);
    }

    const auto length = parse_unsigned(
        text.substr(slash + 1), 32, "IPv4 prefix length");

    Prefix4 prefix;
    prefix.length = static_cast<std::uint8_t>(length);
    prefix.network_be =
        address.s_addr & prefix_mask4(prefix.length);

    return prefix;
}

Prefix6 parse_prefix6(const std::string& text) {
    const auto slash = text.find('/');

    if (slash == std::string::npos) {
        throw std::runtime_error("prefix needs /len: " + text);
    }

    Prefix6 prefix;

    if (::inet_pton(
            AF_INET6,
            text.substr(0, slash).c_str(),
            &prefix.network) != 1) {

        throw std::runtime_error("bad IPv6 prefix: " + text);
    }

    const auto length = parse_unsigned(
        text.substr(slash + 1), 128, "IPv6 prefix length");

    prefix.length = static_cast<std::uint8_t>(length);
    mask_prefix6(prefix.network, prefix.length);

    return prefix;
}

std::string prefix_to_string(const Prefix4& prefix) {
    return
        ipv4_to_string(prefix.network_be) +
        "/" +
        std::to_string(prefix.length);
}

std::string prefix_to_string(const Prefix6& prefix) {
    return
        ipv6_to_string(prefix.network) +
        "/" +
        std::to_string(prefix.length);
}

std::uint64_t prefix_key(const Prefix4& prefix) {
    return
        (static_cast<std::uint64_t>(
            ntohl(prefix.network_be)) << 8U) |
        prefix.length;
}

std::string prefix_key(const Prefix6& prefix) {
    std::string key(
        reinterpret_cast<const char*>(prefix.network.s6_addr),
        16);

    key.push_back(static_cast<char>(prefix.length));
    return key;
}

bool prefix_equal(const Prefix4& left, const Prefix4& right) {
    return
        left.length == right.length and
        left.network_be == right.network_be;
}

bool prefix_equal(const Prefix6& left, const Prefix6& right) {
    return
        left.length == right.length and
        std::memcmp(
            &left.network,
            &right.network,
            sizeof(in6_addr)) == 0;
}

bool prefix_is_within(const Prefix4& prefix, const Prefix4& filter) {
    if (prefix.length < filter.length) {
        return false;
    }

    return
        (prefix.network_be & prefix_mask4(filter.length)) ==
        filter.network_be;
}

bool prefix_is_within(const Prefix6& prefix, const Prefix6& filter) {
    if (prefix.length < filter.length) {
        return false;
    }

    in6_addr masked = prefix.network;
    mask_prefix6(masked, filter.length);

    return
        std::memcmp(
            &masked,
            &filter.network,
            sizeof(in6_addr)) == 0;
}

class Netlink {
public:
    explicit Netlink(unsigned interface_index)
        : interface_index_(interface_index) {

        request_fd_ = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

        if (request_fd_ < 0) {
            fail_errno("netlink socket");
        }

        timeval netlink_timeout {
            netlink_timeout_seconds,
            0,
        };

        if (::setsockopt(
                request_fd_,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &netlink_timeout,
                sizeof(netlink_timeout)) != 0) {

            fail_errno("netlink SO_RCVTIMEO");
        }

        if (::setsockopt(
                request_fd_,
                SOL_SOCKET,
                SO_SNDTIMEO,
                &netlink_timeout,
                sizeof(netlink_timeout)) != 0) {

            fail_errno("netlink SO_SNDTIMEO");
        }

        watch_fd_ = ::socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);

        if (watch_fd_ < 0) {
            fail_errno("netlink watch socket");
        }

        sockaddr_nl address {};
        address.nl_family = AF_NETLINK;
        address.nl_groups =
            RTMGRP_IPV4_ROUTE |
            RTMGRP_IPV6_ROUTE;

        if (::bind(
                watch_fd_,
                reinterpret_cast<sockaddr*>(&address),
                sizeof(address)) != 0) {

            fail_errno("netlink watch bind");
        }
    }

    ~Netlink() {
        if (request_fd_ >= 0) {
            ::close(request_fd_);
        }

        if (watch_fd_ >= 0) {
            ::close(watch_fd_);
        }
    }

    int watch_fd() const {
        return watch_fd_;
    }

    void set_interface_index(unsigned interface_index) {
        interface_index_ = interface_index;
    }

    void drain_watch() {
        std::array<char, 16384> buffer {};

        while (true) {
            const ssize_t received = ::recv(
                watch_fd_,
                buffer.data(),
                buffer.size(),
                MSG_DONTWAIT);

            if (received > 0) {
                continue;
            }

            if (

                received < 0 and
                errno == EINTR) {

                continue;
            }

            return;
        }
    }

    std::vector<Prefix4> dump_routes(const ExportPolicy4& policy) {
        std::vector<Prefix4> result;
        std::unordered_set<std::uint64_t> seen;

        bool complete = false;

        for (int attempt = 0; attempt < netlink_dump_attempts; ++attempt) {
            result.clear();
            seen.clear();

            complete = dump_routes(
                AF_INET,
                [&](const rtmsg& route, const std::uint8_t* data, int length) {
                if (
                    route.rtm_family != AF_INET or
                    route.rtm_table != RT_TABLE_MAIN or
                    route.rtm_type != RTN_UNICAST or
                    route.rtm_protocol == trep_route_protocol) {

                    return;
                }

                if (
                    policy.export_connected and
                    route_uses_interface(route, data, length)) {

                    return;
                }

                Prefix4 prefix;
                prefix.length = route.rtm_dst_len;

                for_each_attribute(
                    data,
                    length,
                    [&](const rtattr& attribute) {
                        if (
                            attribute.rta_type == RTA_DST and
                            RTA_PAYLOAD(&attribute) >=
                                sizeof(prefix.network_be)) {

                            std::memcpy(
                                &prefix.network_be,
                                RTA_DATA(
                                    const_cast<rtattr*>(&attribute)),
                                sizeof(prefix.network_be));
                        }
                    });

                prefix.network_be &= prefix_mask4(prefix.length);

                if (
                    not matches_policy(route, prefix, policy) or
                    not matches_export_filter(prefix, policy.export_filters)) {

                    return;
                }

                if (seen.insert(prefix_key(prefix)).second) {
                    result.push_back(prefix);
                }
                });

            if (complete) {
                break;
            }

            log_debug("trepd: interrupted IPv4 route dump, retrying");
        }

        if (not complete) {
            throw std::runtime_error(
                "netlink IPv4 route dump repeatedly interrupted");
        }

        for (const Prefix4& prefix : policy.exact_routes) {
            if (seen.insert(prefix_key(prefix)).second) {
                result.push_back(prefix);
            }
        }

        return result;
    }

    std::vector<Prefix6> dump_routes(const ExportPolicy6& policy) {
        std::vector<Prefix6> result;
        std::unordered_set<std::string> seen;

        bool complete = false;

        for (int attempt = 0; attempt < netlink_dump_attempts; ++attempt) {
            result.clear();
            seen.clear();

            complete = dump_routes(
                AF_INET6,
                [&](const rtmsg& route, const std::uint8_t* data, int length) {
                if (
                    route.rtm_family != AF_INET6 or
                    route.rtm_table != RT_TABLE_MAIN or
                    route.rtm_type != RTN_UNICAST or
                    route.rtm_protocol == trep_route_protocol) {

                    return;
                }

                if (
                    policy.export_connected and
                    route_uses_interface(route, data, length)) {

                    return;
                }

                Prefix6 prefix;
                prefix.length = route.rtm_dst_len;

                for_each_attribute(
                    data,
                    length,
                    [&](const rtattr& attribute) {
                        if (
                            attribute.rta_type == RTA_DST and
                            RTA_PAYLOAD(&attribute) >=
                                sizeof(prefix.network)) {

                            std::memcpy(
                                &prefix.network,
                                RTA_DATA(
                                    const_cast<rtattr*>(&attribute)),
                                sizeof(prefix.network));
                        }
                    });

                mask_prefix6(prefix.network, prefix.length);

                if (
                    not matches_policy(route, prefix, policy) or
                    not matches_export_filter(prefix, policy.export_filters)) {

                    return;
                }

                if (seen.insert(prefix_key(prefix)).second) {
                    result.push_back(prefix);
                }
                });

            if (complete) {
                break;
            }

            log_debug("trepd: interrupted IPv6 route dump, retrying");
        }

        if (not complete) {
            throw std::runtime_error(
                "netlink IPv6 route dump repeatedly interrupted");
        }

        for (const Prefix6& prefix : policy.exact_routes) {
            if (seen.insert(prefix_key(prefix)).second) {
                result.push_back(prefix);
            }
        }

        return result;
    }

    void add_route(const Prefix4& prefix, std::uint32_t priority) {
        modify_route(
            AF_INET,
            prefix.length,
            &prefix.network_be,
            sizeof(prefix.network_be),
            RTM_NEWROUTE,
                NLM_F_REQUEST |
                NLM_F_ACK |
                NLM_F_CREATE |
                NLM_F_EXCL,
            priority);
    }

    void add_route(const Prefix6& prefix, std::uint32_t priority) {
        modify_route(
            AF_INET6,
            prefix.length,
            &prefix.network,
            sizeof(prefix.network),
            RTM_NEWROUTE,
                NLM_F_REQUEST |
                NLM_F_ACK |
                NLM_F_CREATE |
                NLM_F_EXCL,
            priority);
    }

    void delete_route(const Prefix4& prefix, std::uint32_t priority) {
        modify_route(
            AF_INET,
            prefix.length,
            &prefix.network_be,
            sizeof(prefix.network_be),
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            priority);
    }

    void delete_route(const Prefix6& prefix, std::uint32_t priority) {
        modify_route(
            AF_INET6,
            prefix.length,
            &prefix.network,
            sizeof(prefix.network),
            RTM_DELROUTE,
            NLM_F_REQUEST | NLM_F_ACK,
            priority);
    }

private:
    bool route_uses_interface(
        const rtmsg& route,
        const std::uint8_t* data,
        int length) const {

        if (route.rtm_protocol != RTPROT_KERNEL) {
            return false;
        }

        auto* attribute = reinterpret_cast<const rtattr*>(data);

        while (RTA_OK(attribute, length)) {
            if (
                attribute->rta_type == RTA_OIF and
                RTA_PAYLOAD(attribute) >= sizeof(interface_index_)) {

                unsigned output_interface = 0;
                std::memcpy(
                    &output_interface,
                    RTA_DATA(attribute),
                    sizeof(output_interface));

                return output_interface == interface_index_;
            }

            attribute = RTA_NEXT(attribute, length);
        }

        return false;
    }

    bool matches_export_filter(
        const Prefix4& prefix,
        const std::vector<Prefix4>& filters) {

        if (filters.empty()) {
            return true;
        }

        for (const Prefix4& filter : filters) {
            if (prefix_is_within(prefix, filter)) {
                return true;
            }
        }

        return false;
    }

    bool matches_export_filter(
        const Prefix6& prefix,
        const std::vector<Prefix6>& filters) {

        if (filters.empty()) {
            return true;
        }

        for (const Prefix6& filter : filters) {
            if (prefix_is_within(prefix, filter)) {
                return true;
            }
        }

        return false;
    }

    template<typename Fn>
    void for_each_attribute(
        const std::uint8_t* data,
        int length,
        Fn&& callback) {

        auto* attribute = reinterpret_cast<rtattr*>(
            const_cast<std::uint8_t*>(data));

        while (RTA_OK(attribute, length)) {
            callback(*attribute);
            attribute = RTA_NEXT(attribute, length);
        }
    }

    bool matches_policy(
        const rtmsg& route,
        const Prefix4& prefix,
        const ExportPolicy4& policy) {

        if (prefix.length == 0) {
            if (policy.export_default) {
                return true;
            }

            for (const Prefix4& exact : policy.exact_routes) {
                if (prefix_equal(prefix, exact)) {
                    return true;
                }
            }

            return false;
        }

        bool accepted = false;

        if (
            policy.export_static and
            route.rtm_scope != RT_SCOPE_LINK and
            (
                route.rtm_protocol == RTPROT_STATIC or
                route.rtm_protocol == RTPROT_BOOT or
                route.rtm_protocol == RTPROT_UNSPEC)) {

            accepted = true;
        }

        if (
            not accepted and
            policy.export_connected and
            route.rtm_protocol == RTPROT_KERNEL) {

            accepted = true;
        }

        if (not accepted) {
            for (const Prefix4& filter : policy.filters) {
                if (prefix_is_within(prefix, filter)) {
                    accepted = true;
                    break;
                }
            }
        }

        const bool no_positive_selector =
            policy.exact_routes.empty() and
            policy.filters.empty() and
            not policy.export_static and
            not policy.export_connected;

        if (
            not accepted and
            no_positive_selector and
            prefix.length != 0) {

            accepted = true;
        }

        return accepted;
    }

    bool matches_policy(
        const rtmsg& route,
        const Prefix6& prefix,
        const ExportPolicy6& policy) {

        if (prefix.length == 0) {
            if (policy.export_default) {
                return true;
            }

            for (const Prefix6& exact : policy.exact_routes) {
                if (prefix_equal(prefix, exact)) {
                    return true;
                }
            }

            return false;
        }

        bool accepted = false;

        if (
            policy.export_static and
            route.rtm_scope != RT_SCOPE_LINK and
            (
                route.rtm_protocol == RTPROT_STATIC or
                route.rtm_protocol == RTPROT_BOOT or
                route.rtm_protocol == RTPROT_UNSPEC)) {

            accepted = true;
        }

        if (
            not accepted and
            policy.export_connected and
            route.rtm_protocol == RTPROT_KERNEL) {

            accepted = true;
        }

        if (not accepted) {
            for (const Prefix6& filter : policy.filters) {
                if (prefix_is_within(prefix, filter)) {
                    accepted = true;
                    break;
                }
            }
        }

        const bool no_positive_selector =
            policy.exact_routes.empty() and
            policy.filters.empty() and
            not policy.export_static and
            not policy.export_connected;

        if (
            not accepted and
            no_positive_selector and
            prefix.length != 0) {

            accepted = true;
        }

        return accepted;
    }

    template<typename Fn>
    bool dump_routes(int family, Fn&& callback) {
        struct Request {
            nlmsghdr header {};
            rtmsg route {};
        } request;

        request.header.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
        request.header.nlmsg_type = RTM_GETROUTE;
        request.header.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
        request.header.nlmsg_seq = ++sequence_;

        request.route.rtm_family = static_cast<std::uint8_t>(family);
        request.route.rtm_table = RT_TABLE_MAIN;

        send_netlink(&request, request.header.nlmsg_len);

        bool done = false;
        bool interrupted = false;

        while (not done) {
            std::array<std::uint8_t, 16384> buffer {};

            const ssize_t received = ::recv(
                request_fd_,
                buffer.data(),
                buffer.size(),
                0);

            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("netlink dump recv");
            }

            int remaining = static_cast<int>(received);

            for (
                auto* header = reinterpret_cast<nlmsghdr*>(buffer.data());
                NLMSG_OK(header, remaining);
                header = NLMSG_NEXT(header, remaining)) {

                if (header->nlmsg_seq != sequence_) {
                    continue;
                }

                if (header->nlmsg_flags & NLM_F_DUMP_INTR) {
                    interrupted = true;
                }

                if (header->nlmsg_type == NLMSG_DONE) {
                    done = true;
                    break;
                }

                if (header->nlmsg_type == NLMSG_ERROR) {
                    const auto* error =
                        reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(header));

                    if (error->error != 0) {
                        throw std::runtime_error(
                            "netlink dump: " +
                            std::string(std::strerror(-error->error)));
                    }

                    continue;
                }

                if (header->nlmsg_type != RTM_NEWROUTE) {
                    continue;
                }

                auto* route =
                    reinterpret_cast<rtmsg*>(NLMSG_DATA(header));

                callback(
                    *route,
                    reinterpret_cast<std::uint8_t*>(RTM_RTA(route)),
                    RTM_PAYLOAD(header));
            }
        }

        return not interrupted;
    }

    void append_attribute(
        std::vector<std::uint8_t>& buffer,
        std::uint16_t type,
        const void* data,
        std::size_t data_size) {

        const std::size_t offset = buffer.size();
        const std::size_t length = RTA_LENGTH(data_size);
        const std::size_t aligned_length = RTA_ALIGN(length);

        buffer.resize(offset + aligned_length);

        auto* attribute = reinterpret_cast<rtattr*>(
            buffer.data() + offset);

        attribute->rta_type = type;
        attribute->rta_len =
            static_cast<std::uint16_t>(length);

        std::memcpy(
            RTA_DATA(attribute),
            data,
            data_size);
    }

    void modify_route(
        int family,
        std::uint8_t prefix_length,
        const void* destination,
        std::size_t destination_size,
        std::uint16_t message_type,
        std::uint16_t flags,
        std::uint32_t priority) {

        std::vector<std::uint8_t> attributes;

        if (prefix_length != 0) {
            append_attribute(
                attributes,
                RTA_DST,
                destination,
                destination_size);
        }

        append_attribute(
            attributes,
            RTA_OIF,
            &interface_index_,
            sizeof(interface_index_));

        if (priority != 0) {
            append_attribute(
                attributes,
                RTA_PRIORITY,
                &priority,
                sizeof(priority));
        }

        const std::size_t message_size =
            NLMSG_LENGTH(sizeof(rtmsg)) +
            attributes.size();

        std::vector<std::uint8_t> message(message_size);

        auto* header =
            reinterpret_cast<nlmsghdr*>(message.data());

        auto* route = reinterpret_cast<rtmsg*>(
            message.data() + sizeof(nlmsghdr));

        header->nlmsg_len =
            static_cast<std::uint32_t>(message_size);
        header->nlmsg_type = message_type;
        header->nlmsg_flags = flags;
        header->nlmsg_seq = ++sequence_;

        route->rtm_family = static_cast<std::uint8_t>(family);
        route->rtm_dst_len = prefix_length;
        route->rtm_table = RT_TABLE_MAIN;
        route->rtm_protocol = trep_route_protocol;
        route->rtm_scope = RT_SCOPE_LINK;
        route->rtm_type = RTN_UNICAST;

        std::memcpy(
            message.data() + NLMSG_LENGTH(sizeof(rtmsg)),
            attributes.data(),
            attributes.size());

        send_netlink(message.data(), message.size());
        wait_for_ack(header->nlmsg_seq);
    }

    void send_netlink(const void* data, std::size_t size) {
        sockaddr_nl kernel {};
        kernel.nl_family = AF_NETLINK;

        iovec iov {};
        iov.iov_base = const_cast<void*>(data);
        iov.iov_len = size;

        msghdr message {};
        message.msg_name = &kernel;
        message.msg_namelen = sizeof(kernel);
        message.msg_iov = &iov;
        message.msg_iovlen = 1;

        if (::sendmsg(request_fd_, &message, 0) < 0) {
            fail_errno("netlink sendmsg");
        }
    }

    void wait_for_ack(std::uint32_t sequence) {
        while (true) {
            std::array<std::uint8_t, 4096> buffer {};

            const ssize_t received = ::recv(
                request_fd_,
                buffer.data(),
                buffer.size(),
                0);

            if (received < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("netlink ack recv");
            }

            int remaining = static_cast<int>(received);

            for (
                auto* header = reinterpret_cast<nlmsghdr*>(buffer.data());
                NLMSG_OK(header, remaining);
                header = NLMSG_NEXT(header, remaining)) {

                if (
                    header->nlmsg_seq != sequence or
                    header->nlmsg_type != NLMSG_ERROR) {

                    continue;
                }

                const auto* error =
                    reinterpret_cast<const nlmsgerr*>(NLMSG_DATA(header));

                if (error->error == 0) {
                    return;
                }

                throw std::runtime_error(
                    "netlink route operation: " +
                    std::string(std::strerror(-error->error)));
            }
        }
    }

    unsigned interface_index_ = 0;
    int request_fd_ = -1;
    int watch_fd_ = -1;
    std::uint32_t sequence_ = 0;
};

class TrepDaemon {
public:
    TrepDaemon(
        std::string interface_name,
        Address local,
        Address peer,
        std::uint16_t port,
        std::uint32_t distance,
        ExportPolicy4 policy4,
        ExportPolicy6 policy6)
        :
        interface_name_(std::move(interface_name)),
        local_(local),
        peer_(peer),
        port_(port),
        distance_(distance),
        policy4_(std::move(policy4)),
        policy6_(std::move(policy6)),
        interface_index_(::if_nametoindex(interface_name_.c_str())),
        netlink_(require_interface_index()) {

        const int comparison = compare_addresses(local_, peer_);

        if (comparison == 0) {
            throw std::runtime_error("local equals peer");
        }

        listener_role_ = comparison < 0;
    }

    ~TrepDaemon() {
        clear_learned_routes();
        close_listener();
    }

    void run() {
        log_info(
            "trepd: ", interface_name_, " ",
            address_to_string(local_), " <-> ",
            address_to_string(peer_), " tcp/", port_,
            " role=", (listener_role_ ? "listen" : "connect"),
            " distance=", distance_);

        if (listener_role_) {
            open_listener();
        }

        while (not stop_requested) {
            if (listener_role_) {
                if (not refresh_interface_index()) {
                    close_listener();
                    ::sleep(1);
                    continue;
                }

                if (listen_fd_ < 0) {
                    open_listener();
                }
            }

            int peer_fd = -1;

            try {
                peer_fd =
                    listener_role_
                        ? accept_peer()
                        : connect_peer();

                if (peer_fd < 0) {
                    continue;
                }

                refresh_interface_index();
                configure_tcp(peer_fd);

                log_info("trepd: peer connected");
                run_session(peer_fd);

            } catch (const std::exception& error) {
                std::cerr
                    << "trepd: "
                    << error.what()
                    << "\n";
            }

            if (peer_fd >= 0) {
                ::close(peer_fd);
            }

            clear_learned_routes();

            if (
                not listener_role_ and
                not stop_requested) {

                ::sleep(reconnect_seconds);
            }
        }
    }

private:
    unsigned require_interface_index() {
        if (interface_index_ == 0) {
            throw std::runtime_error(
                "unknown interface: " + interface_name_);
        }

        return interface_index_;
    }

    bool refresh_interface_index() {
        const unsigned current_index =
            ::if_nametoindex(interface_name_.c_str());

        if (current_index == 0) {
            log_debug(
                "trepd: interface ",
                interface_name_,
                " is unavailable");

            return false;
        }

        if (current_index != interface_index_) {
            log_debug(
                "trepd: interface ",
                interface_name_,
                " index changed ",
                interface_index_,
                " -> ",
                current_index);

            close_listener();
            interface_index_ = current_index;
            netlink_.set_interface_index(current_index);
        }

        return true;
    }

    void close_listener() {
        if (listen_fd_ >= 0) {
            ::close(listen_fd_);
            listen_fd_ = -1;
        }
    }

    void bind_to_interface(int fd) {
        if (::setsockopt(
                fd,
                SOL_SOCKET,
                SO_BINDTODEVICE,
                interface_name_.c_str(),
                interface_name_.size() + 1) != 0) {

            fail_errno("SO_BINDTODEVICE");
        }
    }
    void open_listener() {
        listen_fd_ = ::socket(
            local_.family,
            SOCK_STREAM,
            IPPROTO_TCP);

        if (listen_fd_ < 0) {
            fail_errno("listener socket");
        }

        log_debug("trepd: listener socket created fd=", listen_fd_);

        int reuse = 1;

        if (::setsockopt(
                listen_fd_,
                SOL_SOCKET,
                SO_REUSEADDR,
                &reuse,
                sizeof(reuse)) != 0) {

            fail_errno("SO_REUSEADDR");
        }

        log_debug("trepd: SO_REUSEADDR enabled");

        bind_to_interface(listen_fd_);

        log_debug("trepd: listener bound to interface ", interface_name_);

        if (local_.family == AF_INET) {
            sockaddr_in address {};
            address.sin_family = AF_INET;
            address.sin_port = htons(port_);
            address.sin_addr = local_.ipv4;

            if (::bind(
                    listen_fd_,
                    reinterpret_cast<sockaddr*>(&address),
                    sizeof(address)) != 0) {

                fail_errno("listener bind");
            }

            log_debug(
                "trepd: listener bound to ", address_to_string(local_),
                ":", port_);
        } else {
            int ipv6_only = 1;

            ::setsockopt(
                listen_fd_,
                IPPROTO_IPV6,
                IPV6_V6ONLY,
                &ipv6_only,
                sizeof(ipv6_only));

            sockaddr_in6 address {};
            address.sin6_family = AF_INET6;
            address.sin6_port = htons(port_);
            address.sin6_addr = local_.ipv6;
            address.sin6_scope_id = interface_index_;

            if (::bind(
                    listen_fd_,
                    reinterpret_cast<sockaddr*>(&address),
                    sizeof(address)) != 0) {

                fail_errno("listener bind6");
            }

            log_debug(
                "trepd: listener bound to [", address_to_string(local_),
                "]:", port_);
        }

        if (::listen(listen_fd_, 1) != 0) {
            fail_errno("listen");
        }

        log_info("trepd: listening");
    }

    bool peer_matches(const sockaddr_storage& source) const {
        if (
            peer_.family == AF_INET and
            source.ss_family == AF_INET) {

            const auto* address =
                reinterpret_cast<const sockaddr_in*>(&source);

            return
                address->sin_addr.s_addr ==
                peer_.ipv4.s_addr;
        }

        if (
            peer_.family == AF_INET6 and
            source.ss_family == AF_INET6) {

            const auto* address =
                reinterpret_cast<const sockaddr_in6*>(&source);

            return
                std::memcmp(
                    &address->sin6_addr,
                    &peer_.ipv6,
                    sizeof(in6_addr)) == 0;
        }

        return false;
    }

    int accept_peer() {
        while (not stop_requested) {
            pollfd descriptor {};
            descriptor.fd = listen_fd_;
            descriptor.events = POLLIN;

            const int result = ::poll(&descriptor, 1, 1000);

            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("poll listen");
            }

            if (result == 0) {
                continue;
            }

            sockaddr_storage source {};
            socklen_t source_size = sizeof(source);

            const int peer_fd = ::accept(
                listen_fd_,
                reinterpret_cast<sockaddr*>(&source),
                &source_size);

            if (peer_fd < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("accept");
            }

            if (peer_matches(source)) {
                return peer_fd;
            }

            ::close(peer_fd);
        }

        return -1;
    }

    bool connect_with_timeout(
        int fd,
        const sockaddr* address,
        socklen_t address_size) {

        const int original_flags = ::fcntl(fd, F_GETFL, 0);

        if (original_flags < 0) {
            fail_errno("fcntl get connect flags");
        }

        if (::fcntl(fd, F_SETFL, original_flags | O_NONBLOCK) != 0) {
            fail_errno("fcntl set connect flags");
        }

        const int result = ::connect(fd, address, address_size);

        if (result != 0 and errno != EINPROGRESS) {
            return false;
        }

        if (result != 0) {
            pollfd descriptor {};
            descriptor.fd = fd;
            descriptor.events = POLLOUT;

            const int poll_result =
                ::poll(&descriptor, 1, connect_timeout_ms);

            if (poll_result <= 0) {
                if (poll_result == 0) {
                    errno = ETIMEDOUT;
                }

                return false;
            }

            int socket_error = 0;
            socklen_t socket_error_size = sizeof(socket_error);

            if (::getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    &socket_error,
                    &socket_error_size) != 0) {

                fail_errno("getsockopt connect");
            }

            if (socket_error != 0) {
                errno = socket_error;
                return false;
            }
        }

        if (::fcntl(fd, F_SETFL, original_flags) != 0) {
            fail_errno("fcntl restore connect flags");
        }

        return true;
    }

    int connect_peer() {
        while (not stop_requested) {
            if (not refresh_interface_index()) {
                ::sleep(1);
                continue;
            }

            const int peer_fd = ::socket(
                peer_.family,
                SOCK_STREAM,
                IPPROTO_TCP);

            if (peer_fd < 0) {
                fail_errno("connect socket");
            }

            bind_to_interface(peer_fd);

            int result = -1;

            if (peer_.family == AF_INET) {
                sockaddr_in local_address {};
                local_address.sin_family = AF_INET;
                local_address.sin_addr = local_.ipv4;

                if (::bind(
                        peer_fd,
                        reinterpret_cast<sockaddr*>(&local_address),
                        sizeof(local_address)) != 0) {

                    ::close(peer_fd);
                    fail_errno("client bind");
                }

                sockaddr_in peer_address {};
                peer_address.sin_family = AF_INET;
                peer_address.sin_port = htons(port_);
                peer_address.sin_addr = peer_.ipv4;

                result = connect_with_timeout(
                    peer_fd,
                    reinterpret_cast<sockaddr*>(&peer_address),
                    sizeof(peer_address));
            } else {
                sockaddr_in6 local_address {};
                local_address.sin6_family = AF_INET6;
                local_address.sin6_addr = local_.ipv6;
                local_address.sin6_scope_id = interface_index_;

                if (::bind(
                        peer_fd,
                        reinterpret_cast<sockaddr*>(&local_address),
                        sizeof(local_address)) != 0) {

                    ::close(peer_fd);
                    fail_errno("client bind6");
                }

                sockaddr_in6 peer_address {};
                peer_address.sin6_family = AF_INET6;
                peer_address.sin6_port = htons(port_);
                peer_address.sin6_addr = peer_.ipv6;
                peer_address.sin6_scope_id = interface_index_;

                result = connect_with_timeout(
                    peer_fd,
                    reinterpret_cast<sockaddr*>(&peer_address),
                    sizeof(peer_address));
            }

            if (result) {
                return peer_fd;
            }

            log_debug(
                "trepd: connect failed: ",
                std::strerror(errno));

            ::close(peer_fd);
            ::sleep(reconnect_seconds);
        }

        return -1;
    }

    void configure_tcp(int fd) {
        timeval io_timeout {
            io_timeout_seconds,
            0,
        };

        if (::setsockopt(
                fd,
                SOL_SOCKET,
                SO_SNDTIMEO,
                &io_timeout,
                sizeof(io_timeout)) != 0) {

            fail_errno("SO_SNDTIMEO");
        }

        if (::setsockopt(
                fd,
                SOL_SOCKET,
                SO_RCVTIMEO,
                &io_timeout,
                sizeof(io_timeout)) != 0) {

            fail_errno("SO_RCVTIMEO");
        }

        if (::setsockopt(
                fd,
                IPPROTO_TCP,
                TCP_USER_TIMEOUT,
                &tcp_user_timeout_ms,
                sizeof(tcp_user_timeout_ms)) != 0) {

            fail_errno("TCP_USER_TIMEOUT");
        }

        int enabled = 1;
        int idle = 10;
        int interval = 5;
        int count = 3;

        ::setsockopt(
            fd,
            SOL_SOCKET,
            SO_KEEPALIVE,
            &enabled,
            sizeof(enabled));

        ::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPIDLE,
            &idle,
            sizeof(idle));

        ::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPINTVL,
            &interval,
            sizeof(interval));

        ::setsockopt(
            fd,
            IPPROTO_TCP,
            TCP_KEEPCNT,
            &count,
            sizeof(count));
    }

    void run_session(int fd) {
        receive_buffer_.clear();

        send_message(fd, MessageType::hello, nullptr, 0);
        send_snapshot(fd);

        bool routes_dirty = false;
        auto dirty_since = std::chrono::steady_clock::now();

        while (not stop_requested) {
            pollfd descriptors[2] {};

            descriptors[0].fd = fd;
            descriptors[0].events = POLLIN;

            descriptors[1].fd = netlink_.watch_fd();
            descriptors[1].events = POLLIN;

            const int result = ::poll(
                descriptors,
                2,
                debounce_ms);

            if (result < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("poll session");
            }

            if (
                descriptors[0].revents &
                (POLLHUP | POLLERR | POLLNVAL)) {

                throw std::runtime_error("peer disconnected");
            }

            if (descriptors[0].revents & POLLIN) {
                receive_tcp(fd);
            }

            if (descriptors[1].revents & POLLIN) {
                netlink_.drain_watch();

                if (not routes_dirty) {
                    routes_dirty = true;
                    dirty_since = std::chrono::steady_clock::now();
                }
            }

            if (routes_dirty) {
                const auto age =
                    std::chrono::duration_cast<std::chrono::milliseconds>(
                        std::chrono::steady_clock::now() - dirty_since);

                if (age.count() >= debounce_ms) {
                    send_snapshot(fd);
                    routes_dirty = false;
                }
            }
        }
    }

    void send_snapshot(int fd) {
        const auto routes4 = netlink_.dump_routes(policy4_);
        const auto routes6 = netlink_.dump_routes(policy6_);

        send_message(fd, MessageType::sync_begin, nullptr, 0);

        for (const Prefix4& prefix : routes4) {
            WireRoute4 wire {};
            wire.prefix_length = prefix.length;
            wire.network_be = prefix.network_be;

            send_message(
                fd,
                MessageType::route4,
                &wire,
                sizeof(wire));
        }

        for (const Prefix6& prefix : routes6) {
            WireRoute6 wire {};
            wire.prefix_length = prefix.length;
            wire.network = prefix.network;

            send_message(
                fd,
                MessageType::route6,
                &wire,
                sizeof(wire));
        }

        send_message(fd, MessageType::sync_end, nullptr, 0);

        log_debug(
            "trepd: exported ", routes4.size(), " IPv4, ",
            routes6.size(), " IPv6 route(s)");
    }

    void send_message(
        int fd,
        MessageType type,
        const void* payload,
        std::size_t payload_size) {

        if (payload_size > 65535) {
            throw std::runtime_error("TREP frame too large");
        }

        WireHeader header {
            {'T', 'R', 'E', 'P'},
            trep_version,
            static_cast<std::uint8_t>(type),
            htons(static_cast<std::uint16_t>(payload_size)),
        };

        send_all(fd, &header, sizeof(header));

        if (payload_size != 0) {
            send_all(fd, payload, payload_size);
        }
    }

    void send_all(int fd, const void* data, std::size_t size) {
        auto* cursor =
            reinterpret_cast<const std::uint8_t*>(data);

        while (size != 0) {
            const ssize_t sent = ::send(
                fd,
                cursor,
                size,
                MSG_NOSIGNAL);

            if (sent < 0) {
                if (errno == EINTR) {
                    continue;
                }

                fail_errno("send");
            }

            if (sent == 0) {
                throw std::runtime_error("send EOF");
            }

            cursor += sent;
            size -= static_cast<std::size_t>(sent);
        }
    }

    void receive_tcp(int fd) {
        std::array<std::uint8_t, 4096> buffer {};

        const ssize_t received = ::recv(
            fd,
            buffer.data(),
            buffer.size(),
            0);

        if (received == 0) {
            throw std::runtime_error("peer closed");
        }

        if (received < 0) {
            if (errno == EINTR) {
                return;
            }

            fail_errno("recv");
        }

        receive_buffer_.insert(
            receive_buffer_.end(),
            buffer.begin(),
            buffer.begin() + received);

        process_receive_buffer();
    }

    void process_receive_buffer() {
        std::size_t offset = 0;

        while (
            receive_buffer_.size() - offset >=
            sizeof(WireHeader)) {

            WireHeader header {};

            std::memcpy(
                &header,
                receive_buffer_.data() + offset,
                sizeof(header));

            if (
                std::memcmp(header.magic, "TREP", 4) != 0 or
                header.version != trep_version) {

                throw std::runtime_error("bad TREP header");
            }

            const std::size_t payload_size =
                ntohs(header.payload_length_be);

            const std::size_t frame_size =
                sizeof(WireHeader) + payload_size;

            if (
                receive_buffer_.size() - offset <
                frame_size) {

                break;
            }

            process_message(
                static_cast<MessageType>(header.type),
                receive_buffer_.data() +
                    offset +
                    sizeof(WireHeader),
                payload_size);

            offset += frame_size;
        }

        if (offset != 0) {
            receive_buffer_.erase(
                receive_buffer_.begin(),
                receive_buffer_.begin() +
                    static_cast<std::ptrdiff_t>(offset));
        }
    }

    void process_message(
        MessageType type,
        const std::uint8_t* payload,
        std::size_t payload_size) {

        switch (type) {
        case MessageType::hello:
            if (payload_size != 0) {
                throw std::runtime_error("bad HELLO");
            }
            return;

        case MessageType::sync_begin:
            if (payload_size != 0) {
                throw std::runtime_error("bad SYNC_BEGIN");
            }

            pending4_.clear();
            pending6_.clear();
            syncing_ = true;
            return;

        case MessageType::route4:
            if (
                not syncing_ or
                payload_size != sizeof(WireRoute4)) {

                throw std::runtime_error("bad ROUTE4");
            }

            receive_route4(payload);
            return;

        case MessageType::route6:
            if (
                not syncing_ or
                payload_size != sizeof(WireRoute6)) {

                throw std::runtime_error("bad ROUTE6");
            }

            receive_route6(payload);
            return;

        case MessageType::sync_end:
            if (
                payload_size != 0 or
                not syncing_) {

                throw std::runtime_error("bad SYNC_END");
            }

            apply_snapshot();
            syncing_ = false;
            return;
        }

        throw std::runtime_error("unknown TREP message");
    }

    static bool matches_import_filter(
        const Prefix4& prefix,
        const std::vector<Prefix4>& filters) {

        if (filters.empty()) {
            return true;
        }

        for (const Prefix4& filter : filters) {
            if (prefix_is_within(prefix, filter)) {
                return true;
            }
        }

        return false;
    }

    static bool matches_import_filter(
        const Prefix6& prefix,
        const std::vector<Prefix6>& filters) {

        if (filters.empty()) {
            return true;
        }

        for (const Prefix6& filter : filters) {
            if (prefix_is_within(prefix, filter)) {
                return true;
            }
        }

        return false;
    }

    void receive_route4(const std::uint8_t* payload) {
        WireRoute4 wire {};
        std::memcpy(&wire, payload, sizeof(wire));

        if (wire.prefix_length > 32) {
            throw std::runtime_error("bad IPv4 prefix length");
        }

        Prefix4 prefix;
        prefix.length = wire.prefix_length;
        prefix.network_be =
            wire.network_be & prefix_mask4(prefix.length);

        if (
            not matches_import_filter(
                prefix,
                policy4_.import_filters)) {

            return;
        }

        pending4_[prefix_key(prefix)] = prefix;
    }

    void receive_route6(const std::uint8_t* payload) {
        WireRoute6 wire {};
        std::memcpy(&wire, payload, sizeof(wire));

        if (wire.prefix_length > 128) {
            throw std::runtime_error("bad IPv6 prefix length");
        }

        Prefix6 prefix;
        prefix.length = wire.prefix_length;
        prefix.network = wire.network;

        mask_prefix6(prefix.network, prefix.length);

        if (
            not matches_import_filter(
                prefix,
                policy6_.import_filters)) {

            return;
        }

        pending6_[prefix_key(prefix)] = prefix;
    }

    void apply_snapshot() {
        for (auto it = learned4_.begin(); it != learned4_.end();) {
            if (pending4_.find(it->first) == pending4_.end()) {
                netlink_.delete_route(it->second, distance_);

                log_info("trepd: del ", prefix_to_string(it->second));

                it = learned4_.erase(it);
            } else {
                ++it;
            }
        }

        for (auto it = learned6_.begin(); it != learned6_.end();) {
            if (pending6_.find(it->first) == pending6_.end()) {
                netlink_.delete_route(it->second, distance_);

                log_info("trepd: del ", prefix_to_string(it->second));

                it = learned6_.erase(it);
            } else {
                ++it;
            }
        }

        for (const auto& [key, prefix] : pending4_) {
            if (learned4_.find(key) != learned4_.end()) {
                continue;
            }

            netlink_.add_route(prefix, distance_);
            learned4_[key] = prefix;

            log_info(
                "trepd: add ", prefix_to_string(prefix),
                " metric ", distance_);
        }

        for (const auto& [key, prefix] : pending6_) {
            if (learned6_.find(key) != learned6_.end()) {
                continue;
            }

            netlink_.add_route(prefix, distance_);
            learned6_[key] = prefix;

            log_info(
                "trepd: add ", prefix_to_string(prefix),
                " metric ", distance_);
        }

        log_debug(
            "trepd: imported ", learned4_.size(), " IPv4, ",
            learned6_.size(), " IPv6 route(s)");
    }

    void clear_learned_routes() {
        for (const auto& [key, prefix] : learned4_) {
            (void) key;

            try {
                netlink_.delete_route(prefix, distance_);
            } catch (...) {
            }
        }

        for (const auto& [key, prefix] : learned6_) {
            (void) key;

            try {
                netlink_.delete_route(prefix, distance_);
            } catch (...) {
            }
        }

        learned4_.clear();
        learned6_.clear();
    }

    std::string interface_name_;
    Address local_;
    Address peer_;

    std::uint16_t port_ = default_port;
    std::uint32_t distance_ = default_distance;

    ExportPolicy4 policy4_;
    ExportPolicy6 policy6_;

    unsigned interface_index_ = 0;
    bool listener_role_ = false;
    int listen_fd_ = -1;

    Netlink netlink_;

    std::vector<std::uint8_t> receive_buffer_;

    std::unordered_map<std::uint64_t, Prefix4> learned4_;
    std::unordered_map<std::string, Prefix6> learned6_;

    std::unordered_map<std::uint64_t, Prefix4> pending4_;
    std::unordered_map<std::string, Prefix6> pending6_;

    bool syncing_ = false;
};

void usage(const char* program) {
    std::cerr
        << "Usage: "
        << program
        << " <interface> <local-ip> <peer-ip> [options]\n\n"

        << "Transport:\n"
        << "  lower IP listens, higher IP connects\n"
        << "  --port N\n"
        << "  --distance N\n\n"

        << "Logging:\n"
        << "  --debug\n"
        << "  --quiet\n\n"

        << "IPv4 export:\n"
        << "  --to-peer-filter PREFIX\n"
        << "  --to-peer-route PREFIX\n"
        << "  --to-peer-static\n"
        << "  --to-peer-connected\n"
        << "  --to-peer-default\n"
        << "  --export-filter PREFIX\n"
        << "  --import-filter PREFIX\n\n"

        << "IPv6 export:\n"
        << "  --to-peer-filter6 PREFIX\n"
        << "  --to-peer-route6 PREFIX\n"
        << "  --to-peer-static6\n"
        << "  --to-peer-connected6\n"
        << "  --to-peer-default6\n"
        << "  --export-filter6 PREFIX\n"
        << "  --import-filter6 PREFIX\n";
}

std::uint16_t parse_port(const std::string& text) {
    const auto value = parse_unsigned(text, 65535, "port");

    if (value == 0) {
        throw std::runtime_error("bad port: " + text);
    }

    return static_cast<std::uint16_t>(value);
}

std::uint32_t parse_distance(const std::string& text) {
    const auto value = parse_unsigned(text, 0xffffffffULL, "distance");

    return static_cast<std::uint32_t>(value);
}

} // namespace

int main(int argc, char** argv) {
    try {
        if (argc < 4) {
            usage(argv[0]);
            return 1;
        }

        const std::string interface_name = argv[1];
        const Address local = parse_address(argv[2]);
        const Address peer = parse_address(argv[3]);

        std::uint16_t port = default_port;
        std::uint32_t distance = default_distance;

        ExportPolicy4 policy4;
        ExportPolicy6 policy6;

        for (int i = 4; i < argc; ++i) {
            const std::string argument = argv[i];

            auto require_value = [&](const char* option) {
                if (++i >= argc) {
                    throw std::runtime_error(
                        std::string(option) + " needs value");
                }

                return std::string(argv[i]);
            };

            if (argument == "--debug") {
                debug_logging = true;

            } else if (argument == "--quiet") {
                quiet_logging = true;

            } else if (argument == "--port") {
                port = parse_port(require_value("--port"));

            } else if (argument == "--distance") {
                distance = parse_distance(require_value("--distance"));

            } else if (argument == "--to-peer-filter") {
                policy4.filters.push_back(
                    parse_prefix4(require_value("--to-peer-filter")));

            } else if (argument == "--export-filter") {
                policy4.export_filters.push_back(
                    parse_prefix4(require_value("--export-filter")));

            } else if (argument == "--import-filter") {
                policy4.import_filters.push_back(
                    parse_prefix4(require_value("--import-filter")));

            } else if (argument == "--to-peer-route") {
                policy4.exact_routes.push_back(
                    parse_prefix4(require_value("--to-peer-route")));

            } else if (argument == "--to-peer-static") {
                policy4.export_static = true;

            } else if (argument == "--to-peer-connected") {
                policy4.export_connected = true;

            } else if (argument == "--to-peer-default") {
                policy4.export_default = true;

            } else if (argument == "--to-peer-filter6") {
                policy6.filters.push_back(
                    parse_prefix6(require_value("--to-peer-filter6")));

            } else if (argument == "--export-filter6") {
                policy6.export_filters.push_back(
                    parse_prefix6(require_value("--export-filter6")));

            } else if (argument == "--import-filter6") {
                policy6.import_filters.push_back(
                    parse_prefix6(require_value("--import-filter6")));

            } else if (argument == "--to-peer-route6") {
                policy6.exact_routes.push_back(
                    parse_prefix6(require_value("--to-peer-route6")));

            } else if (argument == "--to-peer-static6") {
                policy6.export_static = true;

            } else if (argument == "--to-peer-connected6") {
                policy6.export_connected = true;

            } else if (argument == "--to-peer-default6") {
                policy6.export_default = true;

            } else if (
                argument == "--help" or
                argument == "-h") {

                usage(argv[0]);
                return 0;

            } else {
                throw std::runtime_error(
                    "unknown option: " + argument);
            }
        }

        if (local.family != peer.family) {
            throw std::runtime_error("local/peer family mismatch");
        }

        ::signal(SIGINT, on_signal);
        ::signal(SIGTERM, on_signal);

        TrepDaemon daemon(
            interface_name,
            local,
            peer,
            port,
            distance,
            std::move(policy4),
            std::move(policy6));

        daemon.run();
        return 0;

    } catch (const std::exception& error) {
        std::cerr
            << "trepd: "
            << error.what()
            << "\n";

        return 1;
    }
}
