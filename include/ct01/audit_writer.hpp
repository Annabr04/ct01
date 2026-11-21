// audit_chain writer library (M1 scope): builds valid chains for the verifier and its tests.
// IN scope: GENESIS (reasons provisioning / operator_init only), ordinary EVENT records,
// CHECKPOINT, EPOCH_START rotation, segment files. OUT of scope (refused, DESIGN 5.3/5.4/C7):
// successor / recovery / digest-failure logic, i.e. codes 64, 65, 66, 71, dmethod 4, GENESIS
// reasons 3-6, non-zero recoveries/gaps/dfail counters.
// Signing keys are TEST-ONLY software keys (crypto::TestOnlyP256Signer); production signs in the TPM (M2).
#pragma once

#include "ct01/audit_crypto.hpp"
#include "ct01/audit_record.hpp"
#include "ct01/audit_verify.hpp"

#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace ct01::audit {

// Where sealed records go. One append() per record; must be durable when it returns true.
class RecordSink {
public:
    virtual ~RecordSink() = default;
    virtual bool append(const RecordBytes& rec) = 0;
};

// In-memory segments (tests, fuzz seeds). Rolls like the file sink.
class MemorySink final : public RecordSink {
public:
    explicit MemorySink(std::uint64_t roll_bytes = layout::kSegmentRollBytes) : roll_(roll_bytes) {}
    bool append(const RecordBytes& rec) override;
    void set_chain_id(const ChainId& id) { chain_id_ = id; }
    const std::vector<ChainFile>& files() const { return files_; }
private:
    std::uint64_t roll_;
    ChainId chain_id_{};
    std::vector<ChainFile> files_;
};

// Segment files chain_<chain_id hex>_<8-digit index>.ac in an existing directory (DESIGN 5.1/5.2):
// O_WRONLY|O_CREAT|O_EXCL|O_APPEND|O_NOFOLLOW|O_CLOEXEC, mode 0600, one write() per record, fdatasync per
// record, directory fsync when a segment is created, exclusive flock on <dir>/.lock for the writer's
// lifetime, roll at kSegmentRollBytes; a closed segment is fchmod 0400 + fsync'd. On any error the
// sink is dead (append returns false; never retries fdatasync, A009 F51).
class SegmentDirSink final : public RecordSink {
public:
    static std::unique_ptr<SegmentDirSink> open(const std::string& dir, const ChainId& chain_id, std::string& error,
                                                std::uint64_t roll_bytes = layout::kSegmentRollBytes);
    ~SegmentDirSink() override;
    bool append(const RecordBytes& rec) override;
    bool dead() const { return dead_; }
private:
    SegmentDirSink() = default;
    bool open_segment();
    bool close_segment();
    int dir_fd_ = -1, lock_fd_ = -1, seg_fd_ = -1;
    std::uint32_t index_ = 0;
    std::uint64_t seg_bytes_ = 0, roll_ = 0;
    std::string chain_hex_;
    bool dead_ = false;
};

struct EpochKeys {
    const crypto::TestOnlyP256Signer* signer = nullptr;   // S_e (TEST-ONLY)
    std::optional<Hash> tag_root;                         // R^t_e (TEST-ONLY); K_e derived. nullopt = no tags
    std::uint8_t dmode = layout::kDmodeKeyed;
};

enum class WriteError {
    none, out_of_scope, bad_fields, bad_dmethod, overlap, no_key, sink_failed, dead
};
const char* write_error_name(WriteError e);

class ChainWriter {
public:
    struct GenesisParams {
        ChainId chain_id{};
        std::uint16_t reason = codes::reason::genesis::provisioning;   // only 1 or 2 (others out of scope)
        std::uint8_t actor_class = layout::kActorNone;
        std::uint32_t actor_uid = 0;
        std::uint64_t ts_ms = 0, mono_ms = 0;
        std::uint64_t nv_export = 0;
        Hash allowlist_hash{};
        bool clock_safe = false;
    };
    // Writes GENESIS (epoch 0). nullopt + error when params are out of scope or the sink fails.
    static std::optional<ChainWriter> create(RecordSink& sink, const GenesisParams& g, const EpochKeys& k0, WriteError& err);

    // Ordinary EVENT: caller fills code, reason, subject, count, bytes, actor, digest, dmethod, ts/mono;
    // the writer sets seq/epoch/prev_link/len_bucket rules, quantises 22/23 clocks (C3), drops a 23 exact
    // total below kExactTotalMinFrames frames and refuses an overlapping exact total.
    WriteError append_event(RecordFields f);
    // CHECKPOINT over (prev signed seq, now]; d_agg = aggregate of every EVENT digest (F71).
    WriteError checkpoint(std::uint16_t reason, std::uint64_t ts_ms, std::uint64_t mono_ms);
    // Rotation (3.4): CHECKPOINT epoch_pre, then EPOCH_START (signed by S_e, digest = key id of S_{e+1}).
    WriteError rotate_epoch(const EpochKeys& next, std::uint16_t start_reason, std::uint64_t ts_ms, std::uint64_t mono_ms);

    std::uint64_t next_seq() const { return next_seq_; }
    std::uint32_t epoch() const { return epoch_; }
    const Hash& head_link() const { return prev_link_; }
    const ChainId& chain_id() const { return chain_id_; }
    std::uint64_t last_signed_seq() const { return last_signed_; }

private:
    ChainWriter(RecordSink& s) : sink_(&s) {}
    WriteError emit(RecordFields f);
    RecordSink* sink_;
    ChainId chain_id_{};
    EpochKeys keys_{};
    std::optional<Hash> tag_key_;
    std::uint32_t epoch_ = 0;
    std::uint64_t next_seq_ = 0, last_signed_ = 0, nv_export_ = 0;
    std::uint8_t sflags_signed_ = 0;
    Hash prev_link_{};
    std::vector<Hash> range_digests_;
    std::optional<std::uint64_t> exact_hi_;
    bool dead_ = false;
};

// Test helper: the --pubkeys text for a list of (epoch, first, last, signer).
struct PubKeyLine { std::uint32_t epoch; std::uint64_t first; std::optional<std::uint64_t> last; const crypto::TestOnlyP256Signer* signer; };
std::string pubkeys_text(const std::vector<PubKeyLine>& lines);

// Q9: 0 for len 0, else 1 + ceil(log2(len)) (layout::len_bucket_of). C3: G_xfer quantiser.
inline std::uint64_t quantise_xfer_ms(std::uint64_t ms) { return ms - ms % layout::kXferGranularityMs; }

}  // namespace ct01::audit
