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
    using duckbox::node::ParseListenAddress;

    {
        auto hp = ParseListenAddress("127.0.0.1:4747");
        Expect(hp.first == "127.0.0.1" && hp.second == 4747, "HOST:PORT parses");
        auto http = ParseListenAddress("http://127.0.0.1:9000");
        Expect(http.first == "127.0.0.1" && http.second == 9000, "bind accepts an http:// prefix");
        auto grpc = ParseListenAddress("grpc://node-a.example:4984", "advertised_address",
                                       AddressUse::FlightUrl);
        Expect(grpc.first == "node-a.example" && grpc.second == 4984, "grpc host:port parses");
        auto tls = ParseListenAddress("grpc+tls://10.0.0.7:4984", "lease.advertise",
                                      AddressUse::FlightUrl);
        Expect(tls.first == "10.0.0.7" && tls.second == 4984, "grpc+tls host:port parses");
        auto upper = ParseListenAddress("GRPC://node-a.example:4984", "advertised_address",
                                        AddressUse::FlightUrl);
        Expect(upper.first == "node-a.example" && upper.second == 4984,
               "FlightUrl lowercases the scheme allow-list");
    }

    ExpectReject("", "HOST:PORT is required", "empty address names HOST:PORT");
    ExpectReject("127.0.0.1", "HOST:PORT is required", "missing port names HOST:PORT");

    ExpectReject("http://node-a.example:4984", "scheme must be grpc:// or grpc+tls://",
                 "advertised_address refuses a non-Flight scheme", {}, "advertised_address");
    ExpectReject("node-a.example:4984", "scheme must be grpc:// or grpc+tls://",
                 "scheme-less advertised_address is refused", {}, "advertised_address");
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

    ExpectReject("grpc://leakuser:s3cretLeak@node-a.example:4984", "userinfo",
                 "userinfo is refused", {"leakuser", "s3cretLeak"}, "advertised_address");
}
