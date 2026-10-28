#include "check.hpp"
#include "suite.hpp"

#include "node/daemon_config.hpp"

#include <chrono>
#include <string>
#include <vector>

namespace {

void ExpectReject(const std::string &addr, const std::string &needle, const char *msg,
                  const std::vector<std::string> &secrets = {}, const char *what = "listen") {
    try {
        (void)duckbox::node::ParseListenAddress(addr, what);
        duckbox::test::Expect(false, std::string(msg) + " (no throw)");
    } catch (const std::exception &e) {
        const std::string w = e.what();
        duckbox::test::Expect(w.find(needle) != std::string::npos,
                              std::string(msg) + " names the rule");
        duckbox::test::Expect(w.find(what) != std::string::npos,
                              std::string(msg) + " names the field");
        if (!addr.empty()) {
            duckbox::test::Expect(w.find(addr) == std::string::npos,
                                  std::string(msg) + " does not echo the address");
        }
        for (const auto &s : secrets) {
            duckbox::test::Expect(w.find(s) == std::string::npos,
                                  std::string(msg) + " does not echo credential");
        }
    }
}

} // namespace

void duckbox::test::RunListenAddressTests() {
    using duckbox::node::IsWildcardHost;
    using duckbox::node::ParseListenAddress;

    {
        auto hp = ParseListenAddress("127.0.0.1:4747");
        Expect(hp.first == "127.0.0.1" && hp.second == 4747, "HOST:PORT parses");
        auto hu = ParseListenAddress("http://127.0.0.1:9000");
        Expect(hu.first == "127.0.0.1" && hu.second == 9000, "lowercase http URL parses");
        auto grpc = ParseListenAddress("grpc://node-a.example:4984", "advertised_address");
        Expect(grpc.first == "node-a.example" && grpc.second == 4984, "grpc host:port parses");
        auto tls = ParseListenAddress("grpc+tls://10.0.0.7:4984", "lease.advertise");
        Expect(tls.first == "10.0.0.7" && tls.second == 4984, "grpc+tls host:port parses");
        auto v6 = ParseListenAddress("[2001:db8::1]:4747");
        Expect(v6.first == "2001:db8::1" && v6.second == 4747, "IPv6 HOST:PORT parses");
        auto slash = ParseListenAddress("grpc://node-a.example:4984/");
        Expect(slash.first == "node-a.example" && slash.second == 4984, "trailing / is accepted");
        auto under = ParseListenAddress("duckbox_node-1.svc.cluster.local:4984");
        Expect(under.first == "duckbox_node-1.svc.cluster.local" && under.second == 4984,
               "DNS underscore and hyphen parse");
    }

    ExpectReject("", "HOST:PORT is required", "empty address names HOST:PORT");
    ExpectReject("127.0.0.1", "HOST:PORT is required", "missing port names HOST:PORT");
    ExpectReject("http://127.0.0.1", "HOST:PORT is required",
                 "schemed host without port names HOST:PORT");
    ExpectReject("127.0.0.1:0", "port 0 is not accepted", "port 0 is refused");
    // Arrow may reject >65535 at parse time; either rule is fine and must not echo.
    try {
        (void)ParseListenAddress("127.0.0.1:65536");
        Expect(false, "port 65536 (no throw)");
    } catch (const std::exception &e) {
        const std::string w = e.what();
        Expect(w.find("port out of range") != std::string::npos ||
                   w.find("HOST:PORT is required") != std::string::npos,
               "port 65536 names a port rule");
        Expect(w.find("65536") == std::string::npos, "port 65536 does not echo the value");
    }
    ExpectReject("0:0", "port 0 is not accepted", "host 0 with port 0 is refused");
    ExpectReject("GRPC://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "uppercase GRPC scheme is refused");
    ExpectReject("GRPC+TLS://node-a.example:4984", "scheme is invalid / not accepted",
                 "uppercase GRPC+TLS scheme is refused", {}, "advertised_address");
    ExpectReject("Http://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "mixed-case scheme is refused");

    Expect(IsWildcardHost("0.0.0.0") && IsWildcardHost("::") && IsWildcardHost("[::]"),
           "0.0.0.0 and :: are wildcard binds");
    Expect(IsWildcardHost("0"), "host 0 is a wildcard bind (same as 0.0.0.0)");
    Expect(!IsWildcardHost("127.0.0.1") && !IsWildcardHost("localhost"),
           "loopback is not a wildcard");
    {
        auto z = ParseListenAddress("0:4747");
        Expect(z.first == "0" && z.second == 4747 && IsWildcardHost(z.first),
               "listen 0:4747 is host 0 (wildcard) with a required port");
    }

    ExpectReject("grpc://leakuser:s3cretLeak@node-a.example:4984", "userinfo",
                 "userinfo is refused", {"leakuser", "s3cretLeak"}, "advertised_address");
    ExpectReject("grpc://[v7.s3cretLeak]:4984", "host must be a DNS name or IP address",
                 "IPvFuture / bracketed non-IPv6 is refused", {"s3cretLeak"}, "advertised_address");
    ExpectReject("grpc://s3cret%2DLeak:4984", "host must be a DNS name or IP address",
                 "percent-encoded host is refused so validation uses the canonical host",
                 {"s3cret"}, "advertised_address");
    ExpectReject("grpc://s3cret%25Leak:4984", "host must be a DNS name or IP address",
                 "percent-encoded %25 is refused", {"s3cret"}, "lease.advertise");
    ExpectReject("grpc://:4984", "HOST:PORT is required", "empty host is refused", {},
                 "advertised_address");
    ExpectReject(":4984", "HOST:PORT is required", "scheme-less empty host is refused");
    ExpectReject("grpc://node-a.example:4984/?tok=s3cretLeak", "HOST:PORT only", "query is refused",
                 {"s3cretLeak"});
    ExpectReject("grpc://node-a.example:4984#s3cretLeak", "HOST:PORT only", "fragment is refused",
                 {"s3cretLeak"});
    ExpectReject(std::string(513, 'a') + ":4747", "HOST:PORT is required",
                 "address longer than 512 bytes is refused");

    // O(len) with a 512-byte cap: one Arrow parse + linear scans.
    {
        using clock = std::chrono::steady_clock;
        const std::string sample = "127.0.0.1:4747";
        const auto start = clock::now();
        int port = 0;
        for (int i = 0; i < 10000; ++i) {
            port = ParseListenAddress(sample).second;
        }
        const auto ms =
            std::chrono::duration_cast<std::chrono::milliseconds>(clock::now() - start).count();
        Expect(port == 4747, "timing loop parses");
        Expect(ms < 5000, "10k parses of a 14-byte address finish in under 5s (O(len), cap 512)");
    }
}
