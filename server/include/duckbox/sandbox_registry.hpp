#pragma once

// Named sandbox definition store. Identity is a stable id (acme-analyst),
// not (key, hash). S3 layout next to leases: sandboxes/<id>/v<N>.json
// (immutable) and sandboxes/<id>/current.json (pointer, conditional writes).
// Delete writes a tombstone. Any node can load a definition after failover.
// The daemon never sees lake data or secret values — only refs.

#include "duckbox/daemon_config.hpp"
#include "duckbox/policy.hpp"
#include "duckbox/s3.hpp"

#include <memory>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckbox {

// One version of a named sandbox. spec_yaml is the registry body; secret values never appear.
struct SandboxRecord {
	std::string id;
	std::string key;
	std::string policy_class;
	int version = 0;
	std::string content_hash;
	bool lake_validated = false;
	bool tombstone = false;
	std::string spec_yaml;
	std::string spec_dir;
	std::string etag;
	int64_t created_at_ms = 0; // wall clock of first live version
	int64_t updated_at_ms = 0; // wall clock when this version became current
	int64_t expires_at_ms = 0; // 0 = none; from lifecycle.ttl / expires_at
	int handle_gen = 0;        // ExpireSandbox; not a spec version
	SandboxSpec spec;

	std::string ToJson() const;      // immutable vN.json body
	std::string PointerJson() const; // current.json (id, version, etag, tombstone)
	static SandboxRecord FromJson(const std::string &json);
	void ParseSpec(); // LoadSpecString(spec_yaml); throws PolicyError
};

class SandboxRegistry {
public:
	virtual ~SandboxRegistry() = default;
	// Same content is idempotent; different content on an existing id is ConflictError.
	virtual SandboxRecord Create(SandboxRecord rec) = 0;
	virtual SandboxRecord Get(const std::string &id) = 0; // NotFoundError / hides tombstones
	virtual SandboxRecord Update(SandboxRecord rec) = 0;  // bumps version; ConflictError on CAS fail
	virtual SandboxRecord Delete(const std::string &id) = 0;
	virtual std::vector<SandboxRecord> List() = 0; // live definitions; tombstones omitted
	// Passivate-invalidate: bump handle_gen, keep spec version. Definition stays.
	virtual SandboxRecord Expire(const std::string &id) = 0;
	virtual void RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) = 0;
	virtual bool LakeValidated(const std::string &id, int version) const = 0;
	virtual SandboxRecord GetVersion(const std::string &id, int version) = 0; // immutable vN, including N-1
};

// Process-local registry for tests and daemons with no lease S3.
class MemorySandboxRegistry : public SandboxRegistry {
public:
	SandboxRecord Create(SandboxRecord rec) override;
	SandboxRecord Get(const std::string &id) override;
	SandboxRecord Update(SandboxRecord rec) override;
	SandboxRecord Delete(const std::string &id) override;
	std::vector<SandboxRecord> List() override;
	SandboxRecord Expire(const std::string &id) override;
	void RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) override;
	bool LakeValidated(const std::string &id, int version) const override;
	SandboxRecord GetVersion(const std::string &id, int version) override;

private:
	mutable std::mutex mu_;
	std::unordered_map<std::string, SandboxRecord> recs_;
	std::unordered_map<std::string, std::unordered_map<int, SandboxRecord>> versions_;
	int etag_seq_ = 1;
};

// Control-plane S3 registry. Create uses If-None-Match:*; update uses If-Match etag.
class S3SandboxRegistry : public SandboxRegistry {
public:
	explicit S3SandboxRegistry(LeaseSettings lease);
	explicit S3SandboxRegistry(std::shared_ptr<S3ControlClient> client);

	SandboxRecord Create(SandboxRecord rec) override;
	SandboxRecord Get(const std::string &id) override;
	SandboxRecord Update(SandboxRecord rec) override;
	SandboxRecord Delete(const std::string &id) override;
	std::vector<SandboxRecord> List() override;
	SandboxRecord Expire(const std::string &id) override;
	void RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) override;
	bool LakeValidated(const std::string &id, int version) const override;
	SandboxRecord GetVersion(const std::string &id, int version) override;

private:
	SandboxRecord LoadCurrent(const std::string &id) const;
	SandboxRecord LoadVersionObject(const std::string &id, int version) const;
	void PutVersion(const SandboxRecord &rec);
	void PutCurrent(const SandboxRecord &rec, const std::string &if_match, const std::string &if_none_match);

	std::shared_ptr<S3ControlClient> client_;
	mutable std::mutex mu_;
	mutable std::unordered_map<std::string, SandboxSpec> lake_cache_;
};

std::shared_ptr<SandboxRegistry> MakeSandboxRegistry(const DaemonConfig &daemon); // S3 if lease.bucket set, else memory
SandboxRecord RecordFromSpec(SandboxSpec spec, std::string spec_dir = "");
int64_t WallNowMs();
// Current version always wins. The immediately previous version is accepted
// until current.updated_at_ms + current.spec.handles.stale_version_grace_ms
// (default grace 0 = reject). Older versions always re-prepare.
SandboxRecord ResolveHandleVersion(SandboxRegistry &defs, const SandboxRecord &current, int handle_version,
                                   int64_t now_ms = 0);
void EnsureCurrentVersion(const SandboxRecord &current, int handle_version, const std::string &sandbox_id);
bool IsExpired(const SandboxRecord &rec, int64_t now_ms = 0); // uses WallNowMs when now_ms <= 0
void ApplyLifecycleTimes(SandboxRecord &rec, int64_t now_ms = 0);

} // namespace duckbox
