#include "check.hpp"
#include "suite.hpp"

#include "node/daemon_config.hpp"

#include <string>
#include <vector>

namespace {

void ExpectReject(const std::string &addr, const std::string &needle, const char *msg,
                  const std::vector<std::string> &secrets = {}, const char *what = "listen",
                  int default_port = -1) {
    try {
        const std::string w0 = what;
        const auto use = (w0 == "advertised_address" || w0 == "lease.advertise")
                             ? duckbox::node::AddressUse::FlightUrl
                             : duckbox::node::AddressUse::Bind;
        (void)duckbox::node::ParseListenAddress(addr, what, use, default_port);
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
    using duckbox::node::AddressUse;
    using duckbox::node::IsWildcardHost;
    using duckbox::node::ParseListenAddress;

    {
        auto hp = ParseListenAddress("127.0.0.1:4747");
        Expect(hp.first == "127.0.0.1" && hp.second == 4747, "HOST:PORT parses");
        auto grpc = ParseListenAddress("grpc://node-a.example:4984", "advertised_address",
                                       AddressUse::FlightUrl);
        Expect(grpc.first == "node-a.example" && grpc.second == 4984, "grpc host:port parses");
        auto tls = ParseListenAddress("grpc+tls://10.0.0.7:4984", "lease.advertise",
                                      AddressUse::FlightUrl);
        Expect(tls.first == "10.0.0.7" && tls.second == 4984, "grpc+tls host:port parses");
        auto v6 = ParseListenAddress("[2001:db8::1]:4747");
        Expect(v6.first == "2001:db8::1" && v6.second == 4747, "IPv6 HOST:PORT parses");
        auto slash = ParseListenAddress("grpc://node-a.example:4984/", "advertised_address",
                                        AddressUse::FlightUrl);
        Expect(slash.first == "node-a.example" && slash.second == 4984, "trailing / is accepted");
        auto dns = ParseListenAddress("duckbox-node-1.svc.cluster.local:4984");
        Expect(dns.first == "duckbox-node-1.svc.cluster.local" && dns.second == 4984,
               "DNS hyphen parses");
        auto dbg = ParseListenAddress("127.0.0.1", "debug_http", AddressUse::Bind, 4748);
        Expect(dbg.first == "127.0.0.1" && dbg.second == 4748,
               "debug_http host without port uses default 4748");
    }

    ExpectReject("", "HOST:PORT is required", "empty address names HOST:PORT");
    ExpectReject("127.0.0.1", "HOST:PORT is required", "missing port names HOST:PORT");
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
    ExpectReject("node-zqx.example:0", "port 0 is not accepted", "port 0 does not echo the host",
                 {"node-zqx"});
    ExpectReject("GRPC://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "uppercase GRPC scheme is refused");
    ExpectReject("GRPC+TLS://node-a.example:4984", "scheme is invalid / not accepted",
                 "uppercase GRPC+TLS scheme is refused", {}, "advertised_address");
    ExpectReject("http://node-a.example:4984", "scheme must be grpc:// or grpc+tls://",
                 "advertised_address refuses a non-Flight scheme", {}, "advertised_address");
    try {
        (void)ParseListenAddress("foo://node-a.example:4984", "lease.advertise",
                                 AddressUse::FlightUrl);
        Expect(false, "lease.advertise foo:// (no throw)");
    } catch (const std::exception &e) {
        Expect(std::string(e.what()).find("scheme must be grpc:// or grpc+tls://") !=
                   std::string::npos,
               "lease.advertise refuses a non-Flight scheme");
        Expect(std::string(e.what()).find("foo") == std::string::npos,
               "lease.advertise foo:// does not echo the scheme");
    }
    ExpectReject("http://127.0.0.1:9000", "scheme is invalid / not accepted",
                 "listen refuses an http:// prefix");
    ExpectReject("foo://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "listen refuses foo://", {"foo"});
    ExpectReject("Http://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "mixed-case scheme is refused");
    ExpectReject("http://127.0.0.1:5747", "scheme is invalid / not accepted",
                 "internal_listen refuses an http:// prefix", {"http://"}, "internal_listen");
    ExpectReject("foo://127.0.0.1:9477", "scheme is invalid / not accepted",
                 "metrics.listen refuses foo://", {"foo"}, "metrics.listen");
    ExpectReject("http://127.0.0.1:18480", "scheme is invalid / not accepted",
                 "debug_http refuses an http:// prefix", {"http://"}, "debug_http", 4748);

    Expect(IsWildcardHost("0.0.0.0") && IsWildcardHost("::") && IsWildcardHost("[::]"),
           "0.0.0.0 and :: are wildcard binds");
    Expect(IsWildcardHost("0"), "host 0 is a wildcard bind (same as 0.0.0.0)");
    for (const char *w :
         {"0x0", "00", "0.0", "000.000.000.000", "0x00000000", "::0", "0:0:0:0:0:0:0:0",
          "::ffff:0.0.0.0", "[::0]", "[::ffff:0.0.0.0]", "[0:0:0:0:0:0:0:0]"}) {
        Expect(IsWildcardHost(w), std::string("wildcard spelling is a wildcard bind: ") + w);
    }
    Expect(!IsWildcardHost("::ffff:1.2.3.4") && !IsWildcardHost("[::ffff:1.2.3.4]"),
           "v4-mapped non-zero addresses are not wildcards");
    Expect(!IsWildcardHost("::1") && !IsWildcardHost("10.0.0.7") && !IsWildcardHost("node-a"),
           "non-any addresses are not wildcards");
    Expect(!IsWildcardHost("127.0.0.1") && !IsWildcardHost("localhost"),
           "loopback is not a wildcard");
    {
        auto z = ParseListenAddress("0:4747");
        Expect(z.first == "0" && z.second == 4747 && IsWildcardHost(z.first),
               "listen 0:4747 is host 0 (wildcard) with a required port");
        auto hex = ParseListenAddress("0x0:4747");
        Expect(IsWildcardHost(hex.first), "listen 0x0:4747 is a wildcard bind");
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
                 {"s3cretLeak"}, "advertised_address");
    ExpectReject("127.0.0.1:4747?", "HOST:PORT only", "trailing ? is refused");
    ExpectReject("grpc://node-a.example:4984?", "HOST:PORT only",
                 "advertised_address trailing ? is refused", {}, "advertised_address");
    ExpectReject("grpc://node-a.example:4984#s3cretLeak", "HOST:PORT only", "fragment is refused",
                 {"s3cretLeak"}, "advertised_address");
    ExpectReject(std::string(513, 'a') + ":4747", "HOST:PORT is required",
                 "address longer than 512 bytes is refused");

    ExpectReject("duckbox_node-1.svc.cluster.local:4984", "host must be a DNS name or IP address",
                 "underscore in DNS host is refused");
    ExpectReject("host$.example:4747", "host must be a DNS name or IP address",
                 "non-DNS charset in host is refused");
    ExpectReject("foo..bar:4747", "host must be a DNS name or IP address",
                 "empty DNS label is refused");
    ExpectReject(std::string(64, 'a') + ".example:4747", "host must be a DNS name or IP address",
                 "64-char DNS label is refused");
    {
        const std::string l63(63, 'a');
        auto ok63 = ParseListenAddress(l63 + ".example:4747");
        Expect(ok63.first == l63 + ".example", "63-char DNS label is accepted");
        const std::string n253 = std::string(63, 'a') + "." + std::string(63, 'b') + "." +
                                 std::string(63, 'c') + "." + std::string(61, 'd');
        Expect(ParseListenAddress(n253 + ":4747").first == n253, "253-char DNS name is accepted");
        ExpectReject(n253 + "d:4747", "host must be a DNS name or IP address",
                     "254-char multi-label DNS name is refused");
    }
    for (const char *bad : {"-a", "a-", "-", "a.-b.c"}) {
        ExpectReject(std::string(bad) + ":4747", "host must be a DNS name or IP address",
                     "leading/trailing hyphen in a DNS label is refused (RFC 1123)");
    }
    for (const char *bad :
         {"1.2.3.999", "256.1.1.1", "1.2.3.4.5", "4294967296", "08", "1.2.3.08"}) {
        ExpectReject(std::string(bad) + ":4747", "host must be a DNS name or IP address",
                     "all-numeric host that is not an IP literal is refused");
    }
    Expect(ParseListenAddress("xn--bcher-kva.example:4747").first == "xn--bcher-kva.example",
           "punycode label is accepted");
    Expect(ParseListenAddress("123.example:4747").first == "123.example",
           "numeric non-top label is a DNS name");
    ExpectReject("grpc://127.0.0.1:4747", "scheme is invalid / not accepted",
                 "listen refuses lowercase grpc://", {"grpc://"});
    ExpectReject("grpc://127.0.0.1:5747", "scheme is invalid / not accepted",
                 "internal_listen refuses lowercase grpc://", {"grpc://"}, "internal_listen");
    ExpectReject("grpc://127.0.0.1:9477", "scheme is invalid / not accepted",
                 "metrics.listen refuses lowercase grpc://", {"grpc://"}, "metrics.listen");
    ExpectReject("grpc://127.0.0.1:18480", "scheme is invalid / not accepted",
                 "debug_http refuses lowercase grpc://", {"grpc://"}, "debug_http", 4748);

    {
        auto c = duckbox::node::DefaultDaemonConfig();
        c.advertised_address = "node-a.example:4747";
        duckbox::node::FinalizeDaemonListen(c);
        Expect(c.advertised_address == "grpc://node-a.example:4747",
               "bare HOST:PORT advertised_address is published as grpc://HOST:PORT");
    }

    // The 512-byte cap is the complexity bound; the 513-byte case above proves it.
}
