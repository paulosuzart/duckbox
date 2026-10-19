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
	int64_t updated_at_ms = 0; // wall clock when this version became current
	SandboxSpec spec;

	std::string ToJson() const;
	std::string PointerJson() const;
	static SandboxRecord FromJson(const std::string &json);
	void ParseSpec();
};

class SandboxRegistry {
public:
	virtual ~SandboxRegistry() = default;
	virtual SandboxRecord Create(SandboxRecord rec) = 0;
	virtual SandboxRecord Get(const std::string &id) = 0;
	virtual SandboxRecord Update(SandboxRecord rec) = 0;
	virtual SandboxRecord Delete(const std::string &id) = 0;
	virtual std::vector<SandboxRecord> List() = 0;
	virtual void RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) = 0;
	virtual bool LakeValidated(const std::string &id, int version) const = 0;
	virtual SandboxRecord GetVersion(const std::string &id, int version) = 0;
};

class MemorySandboxRegistry : public SandboxRegistry {
public:
	SandboxRecord Create(SandboxRecord rec) override;
	SandboxRecord Get(const std::string &id) override;
	SandboxRecord Update(SandboxRecord rec) override;
	SandboxRecord Delete(const std::string &id) override;
	std::vector<SandboxRecord> List() override;
	void RememberLakeValidation(const std::string &id, int version, SandboxSpec spec) override;
	bool LakeValidated(const std::string &id, int version) const override;
	SandboxRecord GetVersion(const std::string &id, int version) override;

private:
	mutable std::mutex mu_;
	std::unordered_map<std::string, SandboxRecord> recs_;
	std::unordered_map<std::string, std::unordered_map<int, SandboxRecord>> versions_;
	int etag_seq_ = 1;
};

class S3SandboxRegistry : public SandboxRegistry {
public:
	explicit S3SandboxRegistry(LeaseSettings lease);
	explicit S3SandboxRegistry(std::shared_ptr<S3ControlClient> client);

	SandboxRecord Create(SandboxRecord rec) override;
	SandboxRecord Get(const std::string &id) override;
	SandboxRecord Update(SandboxRecord rec) override;
	SandboxRecord Delete(const std::string &id) override;
	std::vector<SandboxRecord> List() override;
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

std::shared_ptr<SandboxRegistry> MakeSandboxRegistry(const DaemonConfig &daemon);
SandboxRecord RecordFromSpec(SandboxSpec spec, std::string spec_dir = "");
int64_t WallNowMs();
// Current version always wins. The immediately previous version is accepted
// until current.updated_at_ms + current.spec.handles.stale_version_grace_ms
// (default grace 0 = reject). Older versions always re-prepare.
SandboxRecord ResolveHandleVersion(SandboxRegistry &defs, const SandboxRecord &current, int handle_version,
                                   int64_t now_ms = 0);
void EnsureCurrentVersion(const SandboxRecord &current, int handle_version, const std::string &sandbox_id);

} // namespace duckbox
