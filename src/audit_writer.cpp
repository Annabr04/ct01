#include "ct01/audit_writer.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace ct01::audit {

using namespace layout;

const char* write_error_name(WriteError e) {
    switch (e) {
        case WriteError::none: return "none";
        case WriteError::out_of_scope: return "out_of_scope";
        case WriteError::bad_fields: return "bad_fields";
        case WriteError::bad_dmethod: return "bad_dmethod";
        case WriteError::overlap: return "overlap";
        case WriteError::no_key: return "no_key";
        case WriteError::sink_failed: return "sink_failed";
        case WriteError::dead: return "dead";
    }
    return "unknown";
}

namespace {
std::string segment_name(const std::string& chain_hex, std::uint32_t index) {
    char buf[16];
    std::snprintf(buf, sizeof buf, "%08u", index);
    return "chain_" + chain_hex + "_" + buf + ".ac";
}
}  // namespace

bool MemorySink::append(const RecordBytes& rec) {
    if (files_.empty() || files_.back().bytes.size() + rec.size() > roll_ + kSignedRecordSize ||
        files_.back().bytes.size() >= roll_) {
        files_.push_back({segment_name(crypto::to_hex(chain_id_), static_cast<std::uint32_t>(files_.size())), {}});
    }
    files_.back().bytes.insert(files_.back().bytes.end(), rec.begin(), rec.end());
    return true;
}

std::unique_ptr<SegmentDirSink> SegmentDirSink::open(const std::string& dir, const ChainId& chain_id, std::string& error,
                                                     std::uint64_t roll_bytes) {
    std::unique_ptr<SegmentDirSink> s(new SegmentDirSink());
    s->roll_ = roll_bytes;
    s->chain_hex_ = crypto::to_hex(chain_id);
    s->dir_fd_ = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (s->dir_fd_ < 0) { error = std::string("open dir: ") + std::strerror(errno); return nullptr; }
    s->lock_fd_ = ::openat(s->dir_fd_, ".lock", O_RDWR | O_CREAT | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (s->lock_fd_ < 0) { error = std::string("open .lock: ") + std::strerror(errno); return nullptr; }
    if (::flock(s->lock_fd_, LOCK_EX | LOCK_NB) != 0) { error = "chain lock busy"; return nullptr; }
    if (!s->open_segment()) { error = std::string("create segment: ") + std::strerror(errno); return nullptr; }
    return s;
}

SegmentDirSink::~SegmentDirSink() {
    if (seg_fd_ >= 0) ::close(seg_fd_);
    if (lock_fd_ >= 0) ::close(lock_fd_);   // releases the flock
    if (dir_fd_ >= 0) ::close(dir_fd_);
}

bool SegmentDirSink::open_segment() {
    const std::string name = segment_name(chain_hex_, index_);
    seg_fd_ = ::openat(dir_fd_, name.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_APPEND | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (seg_fd_ < 0) return false;
    seg_bytes_ = 0;
    return ::fsync(dir_fd_) == 0;   // the new directory entry is durable
}

bool SegmentDirSink::close_segment() {
    const bool ok = ::fchmod(seg_fd_, 0400) == 0 && ::fsync(seg_fd_) == 0;
    ::close(seg_fd_);
    seg_fd_ = -1;
    return ok;
}

bool SegmentDirSink::append(const RecordBytes& rec) {
    if (dead_) return false;
    if (seg_bytes_ >= roll_) {
        ++index_;
        if (!close_segment() || !open_segment()) { dead_ = true; return false; }
    }
    const ssize_t n = ::write(seg_fd_, rec.data(), rec.size());   // one write per record
    if (n != static_cast<ssize_t>(rec.size()) || ::fdatasync(seg_fd_) != 0) {
        dead_ = true;   // never retry fdatasync (A009 F51): the caller starts a successor (out of M1 scope)
        return false;
    }
    seg_bytes_ += rec.size();
    return true;
}

std::optional<ChainWriter> ChainWriter::create(RecordSink& sink, const GenesisParams& g, const EpochKeys& k0, WriteError& err) {
    err = WriteError::none;
    if (g.reason != codes::reason::genesis::provisioning && g.reason != codes::reason::genesis::operator_init) {
        err = WriteError::out_of_scope;   // successor GENESIS (reasons 3-6) is out of M1 scope
        return std::nullopt;
    }
    if (!k0.signer) { err = WriteError::no_key; return std::nullopt; }
    ChainWriter w(sink);
    w.chain_id_ = g.chain_id;
    w.keys_ = k0;
    if (k0.tag_root) w.tag_key_ = derive_epoch_key(g.chain_id, *k0.tag_root, 0);
    w.nv_export_ = g.nv_export;
    w.sflags_signed_ = g.clock_safe ? kSflagClockSafe : 0;
    if (auto* m = dynamic_cast<MemorySink*>(&sink)) m->set_chain_id(g.chain_id);
    RecordFields f;
    f.rec_type = kRtGenesis;
    f.event_code = code::genesis;
    f.reason = g.reason;
    f.actor_class = g.actor_class;
    f.actor_uid = g.actor_uid;
    f.dmethod = kDmNotApplicable;
    f.dmode = k0.dmode;
    f.ts_ms = g.ts_ms;
    f.mono_ms = g.mono_ms;
    const Hash kid = software_key_id(k0.signer->public_sec1());
    std::memcpy(f.digest.data(), g.chain_id.data(), kChainIdSize);
    std::memcpy(f.digest.data() + kChainIdSize, kid.data(), kGenesisKeyIdPrefix);
    f.d_agg = crypto::sha256({crypto::span(kDsGenesis), crypto::span(Hash{}), crypto::span(g.allowlist_hash)});
    err = w.emit(f);
    if (err != WriteError::none) return std::nullopt;
    return w;
}

WriteError ChainWriter::emit(RecordFields f) {
    if (dead_) return WriteError::dead;
    f.seq = next_seq_;
    f.epoch = f.rec_type == kRtEpochStart ? epoch_ + 1 : epoch_;
    f.prev_link = prev_link_;
    f.rec_len = static_cast<std::uint32_t>(record_size_for(f.rec_type));
    if (is_signed_type(f.rec_type)) {
        f.sflags = sflags_signed_;
        f.nv_export = nv_export_;
    }
    if (check_record_fields(f) != Reason::none) return WriteError::bad_fields;
    const Hash* tk = tag_key_ ? &*tag_key_ : nullptr;
    Sealed s = seal_record(f, chain_id_, tk, is_signed_type(f.rec_type) ? keys_.signer : nullptr);
    if (!sink_->append(s.bytes)) { dead_ = true; return WriteError::sink_failed; }
    prev_link_ = s.link;
    ++next_seq_;
    if (is_signed_type(f.rec_type)) {
        last_signed_ = f.seq;
        range_digests_.clear();
    } else {
        range_digests_.push_back(f.digest);
    }
    return WriteError::none;
}

WriteError ChainWriter::append_event(RecordFields f) {
    f.rec_type = kRtEvent;
    const auto c = f.event_code;
    if (c == code::chain_torn_tail_recovered || c == code::chain_predecessor || c == code::chain_gap ||
        c == code::tpm_recovered || f.dmethod == kDmKeyedFailed)
        return WriteError::out_of_scope;   // recovery / successor / digest-failure logic (not M1)
    const EventSpec* sp = find_event_spec(c);
    if (!sp || sp->rec_type != kRtEvent) return WriteError::bad_fields;
    f.dmode = 0;
    f.sflags = 0;
    // dmethod vs the epoch dmode (C4)
    if (sp->digest == Digest::bearing || (sp->digest == Digest::optional && f.dmethod != kDmNotApplicable)) {
        const bool ok = keys_.dmode == kDmodeKeyed ? f.dmethod == kDmKeyed : f.dmethod == kDmAbsent;
        if (!ok) return WriteError::bad_dmethod;
        if (f.dmethod == kDmAbsent) f.digest = Hash{};
    }
    if (sp->ts_coarse) {   // C3: transfer clocks quantised to G_xfer
        f.ts_ms = quantise_xfer_ms(f.ts_ms);
        f.mono_ms = quantise_xfer_ms(f.mono_ms);
    }
    if (c == code::recv_transfer_end) {
        if (f.count < kExactTotalMinFrames) f.bytes = 0;   // exact totals only for >= 32 frames
        if (f.bytes != 0) {
            if (exact_hi_ && f.subj_first <= *exact_hi_) return WriteError::overlap;
        }
    }
    const WriteError e = emit(f);
    if (e == WriteError::none && c == code::recv_transfer_end && f.bytes != 0)
        exact_hi_ = std::max(exact_hi_.value_or(0), f.subj_last);
    return e;
}

WriteError ChainWriter::checkpoint(std::uint16_t reason, std::uint64_t ts_ms, std::uint64_t mono_ms) {
    if (reason == codes::reason::checkpoint::recovery || reason == codes::reason::checkpoint::successor ||
        reason == codes::reason::checkpoint::level4_entry || reason == codes::reason::checkpoint::level4_exit)
        return WriteError::out_of_scope;
    RecordFields f;
    f.rec_type = kRtCheckpoint;
    f.event_code = code::checkpoint;
    f.reason = reason;
    f.dmethod = kDmNotApplicable;
    f.dmode = keys_.dmode;
    f.ts_ms = ts_ms;
    f.mono_ms = mono_ms;
    f.subj_first = last_signed_;
    f.subj_last = next_seq_;
    f.count = static_cast<std::uint32_t>(next_seq_ - last_signed_);
    f.digest = software_key_id(keys_.signer->public_sec1());
    f.d_agg = compute_dagg(range_digests_);   // F71: every EVENT digest, zeros included
    return emit(f);
}

WriteError ChainWriter::rotate_epoch(const EpochKeys& next, std::uint16_t start_reason, std::uint64_t ts_ms, std::uint64_t mono_ms) {
    if (!next.signer) return WriteError::no_key;
    if (WriteError e = checkpoint(codes::reason::checkpoint::epoch_pre, ts_ms, mono_ms); e != WriteError::none) return e;
    RecordFields f;
    f.rec_type = kRtEpochStart;
    f.event_code = code::epoch_start;
    f.reason = start_reason;
    f.dmethod = kDmNotApplicable;
    f.dmode = next.dmode;
    f.ts_ms = ts_ms;
    f.mono_ms = mono_ms;
    f.digest = software_key_id(next.signer->public_sec1());   // S_{e+1} key id
    // tag of EPOCH_START: the new epoch's key K_{e+1} (record epoch = e+1); signed by S_e.
    std::optional<Hash> new_tag;
    if (next.tag_root) new_tag = derive_epoch_key(chain_id_, *next.tag_root, epoch_ + 1);
    tag_key_ = new_tag;
    const WriteError e = emit(f);
    if (e != WriteError::none) return e;
    ++epoch_;
    keys_ = next;
    return WriteError::none;
}

std::string pubkeys_text(const std::vector<PubKeyLine>& lines) {
    std::string s = "ct01-audit-pubkeys v1\n# TEST-ONLY software keys generated by the test\n";
    for (const auto& l : lines) {
        s += "epoch=" + std::to_string(l.epoch) + " first=" + std::to_string(l.first) +
             " last=" + (l.last ? std::to_string(*l.last) : std::string("open")) +
             " key_id=" + crypto::to_hex(software_key_id(l.signer->public_sec1())) +
             " pub=" + crypto::to_hex(l.signer->public_sec1()) + "\n";
    }
    return s;
}

}  // namespace ct01::audit
