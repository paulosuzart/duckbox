#include "suite.hpp"
#include "check.hpp"

#include <arpa/inet.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <netinet/in.h>
#include <signal.h>
#include <string>
#include <sys/socket.h>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

std::string DuckboxBin() {
	if (const char *env = std::getenv("DUCKBOX_BIN")) {
		if (env[0] != '\0') {
			return env;
		}
	}
#ifdef DUCKBOX_BIN_PATH
	if (::access(DUCKBOX_BIN_PATH, X_OK) == 0) {
		return DUCKBOX_BIN_PATH;
	}
#endif
	std::string cov = std::string(DUCKBOX_SOURCE_DIR) + "/build-cov/duckbox";
	if (::access(cov.c_str(), X_OK) == 0) {
		return cov;
	}
	return std::string(DUCKBOX_SOURCE_DIR) + "/build/duckbox";
}

bool PortOpen(int port) {
	int fd = ::socket(AF_INET, SOCK_STREAM, 0);
	if (fd < 0) {
		return false;
	}
	sockaddr_in addr{};
	addr.sin_family = AF_INET;
	addr.sin_port = htons(static_cast<uint16_t>(port));
	::inet_pton(AF_INET, "127.0.0.1", &addr.sin_addr);
	int rc = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
	::close(fd);
	return rc == 0;
}

bool WaitPort(int port, int timeout_ms) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	while (std::chrono::steady_clock::now() < deadline) {
		if (PortOpen(port)) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return false;
}

pid_t StartNode(const std::string &listen, const std::string &internal) {
	pid_t pid = ::fork();
	if (pid == 0) {
		std::string bin = DuckboxBin();
		std::string daemon = std::string(DUCKBOX_SOURCE_DIR) + "/daemons/memory.yaml";
		::execl(bin.c_str(), "duckbox", "serve", "--daemon", daemon.c_str(), "--listen", listen.c_str(),
		        "--internal-listen", internal.c_str(), "--no-metrics", static_cast<char *>(nullptr));
		_exit(127);
	}
	return pid;
}

bool WaitExited(pid_t pid, int *status, int timeout_ms) {
	auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(timeout_ms);
	while (std::chrono::steady_clock::now() < deadline) {
		pid_t w = ::waitpid(pid, status, WNOHANG);
		if (w == pid) {
			return true;
		}
		std::this_thread::sleep_for(std::chrono::milliseconds(50));
	}
	return false;
}

void ForceKill(pid_t pid) {
	if (pid <= 0) {
		return;
	}
	::kill(pid, SIGKILL);
	int st = 0;
	::waitpid(pid, &st, 0);
}

void ExpectSignalExit(pid_t pid, int sig, const std::string &name) {
	duckbox::test::Expect(::kill(pid, sig) == 0, name + " signal delivered");
	int status = 0;
	if (!WaitExited(pid, &status, 8000)) {
		ForceKill(pid);
		duckbox::test::Expect(false, name + " exited within 8s (no SIGKILL)");
		return;
	}
	duckbox::test::Expect(WIFEXITED(status) && WEXITSTATUS(status) == 0, name + " exits 0 after signal");
}

} // namespace

void duckbox::test::RunSignalShutdownTests() {
	if (std::getenv("DUCKBOX_HANDLE_SECRET") == nullptr) {
		::setenv("DUCKBOX_HANDLE_SECRET", "duckbox-dev-secret", 0);
	}
	if (::access(DuckboxBin().c_str(), X_OK) != 0) {
		Expect(false, "duckbox binary is required (build target duckbox)");
		return;
	}

	{
		auto cmd = DuckboxBin() + " run --init-sql x --spec /dev/null --key t --sql SELECT 2>&1";
		FILE *pipe = popen(cmd.c_str(), "r");
		Expect(pipe != nullptr, "popen duckbox run --init-sql");
		std::string out;
		char buf[256];
		while (pipe && fgets(buf, sizeof(buf), pipe) != nullptr) {
			out += buf;
		}
		int rc = pipe ? pclose(pipe) : -1;
		Expect(rc != 0, "--init-sql is a CLI parse error");
		Expect(out.find("init-sql") != std::string::npos || out.find("not expected") != std::string::npos,
		       "--init-sql unknown option is reported");
	}

	pid_t a = 0;
	pid_t b = 0;
	bool listening = false;
	for (int attempt = 0; attempt < 5 && !listening; attempt++) {
		const int base =
		    18000 + static_cast<int>((::getpid() + attempt * 17) % 400) * 4;
		const int pub_a = base;
		const int int_a = base + 1;
		const int pub_b = base + 2;
		const int int_b = base + 3;
		ForceKill(a);
		ForceKill(b);
		a = StartNode("127.0.0.1:" + std::to_string(pub_a),
		              "127.0.0.1:" + std::to_string(int_a));
		b = StartNode("127.0.0.1:" + std::to_string(pub_b),
		              "127.0.0.1:" + std::to_string(int_b));
		if (a <= 0 || b <= 0) {
			continue;
		}
		listening = WaitPort(pub_a, 8000) && WaitPort(int_a, 2000) &&
		            WaitPort(pub_b, 8000) && WaitPort(int_b, 2000);
		if (!listening) {
			ForceKill(a);
			ForceKill(b);
			a = 0;
			b = 0;
		}
	}
	Expect(a > 0 && b > 0, "two nodes fork");
	if (!listening) {
		ForceKill(a);
		ForceKill(b);
		Expect(false, "both nodes listen on public and internal ports");
		return;
	}

	ExpectSignalExit(a, SIGINT, "node-a SIGINT");
	Expect(::kill(b, 0) == 0, "node-b still running after node-a SIGINT");
	ExpectSignalExit(b, SIGTERM, "node-b SIGTERM");
}
