// audit_chain verifier, DESIGN v0.3.3 6.2. Per-record order: length -> structure -> crc ->
// fields -> seq/epoch -> link -> tag -> sig (pinned range) -> counters/flags at signed records.
//
// DESIGN v0.3.4 (A011): reason numbers from Appendix A (codes.hpp, F66); forward-seq contiguity is a
// warning except for a level-4 66 that under-covers (F70); d_agg = aggregate of EVERY EVENT digest in
// (prev signed seq, this seq] in every dmode (F71).
#include "ct01/audit_verify.hpp"

#include "ct01/audit_crypto.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <set>
#include <unordered_map>

namespace ct01::audit {

using namespace layout;

std::vector<std::string> Report::qualifiers() const {
    std::vector<std::string> q;
    if (outcome.fail || outcome.io_or_usage_error) return q;
    if (outcome.recovered) q.emplace_back("recovered");
    if (outcome.gap) q.emplace_back("gap");
    if (outcome.successor) q.emplace_back("successor");
    if (outcome.digest_failed) q.emplace_back("digest_failed");
    if (outcome.tail_unverified) q.emplace_back("tail_unverified");
    if (outcome.unanchored) q.emplace_back("unanchored");
    if (outcome.torn_tail) q.emplace_back("torn_tail");
    return q;
}

namespace {

struct Failure { Reason reason; std::uint64_t seq; };

bool basename_chain_hex(const std::string& name, std::string& hex) {
    // chain_<32 hex>_<8 digits>.ac
    if (name.size() != 6 + 32 + 1 + 8 + 3 || name.compare(0, 6, "chain_") != 0 || name[38] != '_' ||
        name.compare(47, 3, ".ac") != 0)
        return false;
    for (std::size_t i = 39; i < 47; ++i)
        if (name[i] < '0' || name[i] > '9') return false;
    hex = name.substr(6, 32);
    std::uint8_t tmp[16];
    return crypto::from_hex(hex, tmp, 16);
}

class Verifier {
public:
    Verifier(const std::vector<ChainFile>& files, const VerifyOptions& opt) : files_(files), opt_(opt) {}
    Report run();

private:
    const std::vector<ChainFile>& files_;
    const VerifyOptions& opt_;
    Report rep_;

    // chain state
    bool started_ = false;
    ChainId chain_id_{};
    Hash prev_link_{};
    std::uint64_t next_seq_ = 0;
    std::uint64_t first_seq_ = 0;
    std::uint32_t cur_epoch_ = 0;
    std::optional<std::uint8_t> epoch_dmode_;
    std::uint8_t prev_rec_type_ = 0;
    std::optional<std::uint64_t> last_signed_;
    std::vector<std::pair<std::uint64_t, std::uint8_t>> pending_dmethod_;   // pruned start, dmode unknown
    // signed-record counters
    bool have_counters_ = false;
    std::uint32_t c_rec_ = 0, c_gaps_ = 0, c_dfail_ = 0;
    std::uint64_t c_nv_ = 0;
    std::uint64_t dm4_since_signed_ = 0;
    std::optional<bool> lineage_bit1_;
    // 71 tpm_recovered
    std::optional<Hash> last_keyed_link_;
    struct Run { std::uint64_t first, last, count; std::optional<Hash> anchor; };
    std::optional<Run> dm4_run_;
    // C3 exact totals
    std::optional<std::uint64_t> exact_hi_;
    // 75 ladder
    std::optional<int> level_;
    bool level4_gap_done_ = true;
    // records seen (for 69 references): code, reason, dmethod-4
    struct Seen { std::uint16_t code; std::uint16_t reason; bool dm4; };
    std::unordered_map<std::uint64_t, Seen> seen_;
    // F70 forward-seq expectation E (unknown at the start of every verification)
    std::optional<std::uint64_t> fwd_expect_;
    std::set<std::uint32_t> unpinned_warned_;
    // F71 EVENT digests since the previous signed record; complete only if that record was seen
    std::vector<Hash> range_digests_;
    bool dagg_range_complete_ = false;
    // tail coverage
    std::optional<std::uint64_t> first_untagged_after_signed_;
    // clocks
    std::optional<std::uint64_t> last_ts_;
    std::unordered_map<std::uint32_t, std::uint32_t> reset_count_by_epoch_;
    // keys
    std::unordered_map<std::uint32_t, Hash> tag_key_cache_;
    std::optional<Hash> anchor_link_seen_;

    void warn(const char* code, std::uint64_t seq) {
        ++rep_.warnings_total;
        if (rep_.warnings.size() < kMaxWarnings) rep_.warnings.push_back({code, seq});
    }
    const Hash* tag_key(std::uint32_t epoch);
    std::optional<Failure> process(const std::uint8_t* p, std::size_t n, std::size_t file_index, bool first_in_file);
    std::optional<Failure> check_dmethod_vs_dmode(std::uint16_t code, std::uint8_t dmethod, std::uint8_t dmode, std::uint64_t seq);
    std::optional<Failure> check_signed(const RecordFields& f, const Hash& h);
    std::optional<Failure> check_event_chain_rules(const RecordFields& f, const Hash& h);
    std::optional<Failure> check_forward_contiguity(const RecordFields& f);
    std::optional<Failure> check_dagg(const RecordFields& f);
    void note_epoch(const RecordFields& f, bool tag_checked);
};

const Hash* Verifier::tag_key(std::uint32_t epoch) {
    auto it = tag_key_cache_.find(epoch);
    if (it != tag_key_cache_.end()) return &it->second;
    auto k = opt_.tag_keys.find(epoch);
    if (k != opt_.tag_keys.end()) return &(tag_key_cache_[epoch] = k->second);
    auto r = opt_.tag_roots.find(epoch);
    if (r != opt_.tag_roots.end()) return &(tag_key_cache_[epoch] = derive_epoch_key(chain_id_, r->second, epoch));
    return nullptr;
}

void Verifier::note_epoch(const RecordFields& f, bool tag_checked) {
    if (rep_.epochs.empty() || rep_.epochs.back().epoch != f.epoch) {
        ++rep_.epochs_total;
        if (rep_.epochs.size() >= kMaxEpochs) return;
        EpochSummary e;
        e.epoch = f.epoch;
        e.first_seq = f.seq;
        e.dmode = epoch_dmode_.value_or(0);
        rep_.epochs.push_back(e);
    }
    auto& e = rep_.epochs.back();
    if (e.epoch != f.epoch) return;   // capped
    e.last_seq = f.seq;
    ++e.records;
    e.dmode = epoch_dmode_.value_or(0);
    e.tag_checked = e.tag_checked || tag_checked;
}

std::optional<Failure> Verifier::check_dmethod_vs_dmode(std::uint16_t code, std::uint8_t dm, std::uint8_t dmode,
                                                        std::uint64_t seq) {
    const EventSpec* s = find_event_spec(code);
    if (s->digest == Digest::bearing) {
        const bool ok = dmode == kDmodeKeyed ? (dm == kDmKeyed || dm == kDmKeyedFailed) : dm == kDmAbsent;
        if (!ok) return Failure{Reason::e_dmethod, seq};
    } else if (s->digest == Digest::optional) {
        const bool ok = dm == kDmNotApplicable ||
                        (dmode == kDmodeKeyed ? (dm == kDmKeyed || dm == kDmKeyedFailed) : dm == kDmAbsent);
        if (!ok) return Failure{Reason::e_dmethod, seq};
    }
    return std::nullopt;
}

std::optional<Failure> Verifier::check_signed(const RecordFields& f, const Hash& h) {
    const std::uint64_t s = f.seq;
    // signature (pinned range); EPOCH_START is signed by S_{e-1}
    const std::uint32_t signer_epoch = f.rec_type == kRtEpochStart ? f.epoch - 1 : f.epoch;
    const PubKeyEntry* k = opt_.pubkeys->find(signer_epoch);
    if (!k) return Failure{Reason::e_sig, s};   // unknown/missing pubkey (A012 F77); never learned from the chain
    if (s < k->first || s > k->last) return Failure{Reason::e_epoch, s};
    if (!crypto::sig_scalars_in_range(f.sig)) return Failure{Reason::e_sig, s};
    if (!k->key.verify_prehashed(signed_message_digest(h), f.sig)) return Failure{Reason::e_sig, s};
    // key-id claims (4.1/4.2): compared with --pubkeys, never trusted
    if (!k->key_id_pinned) {
        if (unpinned_warned_.insert(signer_epoch).second) warn("key_id_unpinned", s);
    } else if (f.rec_type == kRtGenesis) {
        if (std::memcmp(f.digest.data() + kChainIdSize, k->key_id.data(), kGenesisKeyIdPrefix) != 0)
            return Failure{Reason::e_genesis, s};
    } else if (f.rec_type == kRtCheckpoint) {
        if (f.digest != k->key_id) return Failure{Reason::e_sig, s};
    }
    if (f.rec_type == kRtEpochStart) {
        const PubKeyEntry* nk = opt_.pubkeys->find(f.epoch);
        // a key announced only in EPOCH_START is rejected; unknown/missing pubkey = e_sig (A012 F77)
        if (!nk) return Failure{Reason::e_sig, s};
        if (nk->key_id_pinned && f.digest != nk->key_id) return Failure{Reason::e_epoch_handover, s};
    }
    // sticky flags + counters (6.2 per-code table, A011 F72 for pruned starts)
    const bool bit1 = (f.sflags & kSflagSuccessor) != 0;
    if (lineage_bit1_ && *lineage_bit1_ != bit1) return Failure{Reason::e_flag, s};
    lineage_bit1_ = bit1;
    if (have_counters_) {
        if (f.recoveries_total < c_rec_ || f.gaps_total < c_gaps_ || f.dfail_total < c_dfail_ || f.nv_export < c_nv_)
            return Failure{Reason::e_counter, s};
        const std::uint64_t want = std::min<std::uint64_t>(std::uint64_t{c_dfail_} + dm4_since_signed_, kCounterSaturated);
        if (f.dfail_total != want) return Failure{Reason::e_counter, s};
    } else if (rep_.pruned_start) {
        if (f.dfail_total < std::min<std::uint64_t>(dm4_since_signed_, kCounterSaturated)) return Failure{Reason::e_counter, s};
        warn("counters_base_pruned", s);   // F72: exactness only from GENESIS
    }
    // bit2 iff dfail_total > 0 is a field rule (check_record_fields); never clears follows from non-decrease.
    if (f.rec_type == kRtCheckpoint) {
        if (last_signed_ && f.subj_first != *last_signed_) return Failure{Reason::e_ckpt_range, s};
        if (!last_signed_ && !rep_.pruned_start) return Failure{Reason::e_ckpt_range, s};
        if (f.subj_last != s) return Failure{Reason::e_ckpt_range, s};
        if (auto fl = check_dagg(f)) return fl;   // v0.3.4: no dmode-2 zero rule (withdrawn, F71)
    }
    have_counters_ = true;
    c_rec_ = f.recoveries_total;
    c_gaps_ = f.gaps_total;
    c_dfail_ = f.dfail_total;
    c_nv_ = f.nv_export;
    dm4_since_signed_ = 0;
    range_digests_.clear();
    dagg_range_complete_ = true;
    last_signed_ = s;
    first_untagged_after_signed_.reset();
    rep_.recoveries_total = f.recoveries_total;
    rep_.gaps_total = f.gaps_total;
    rep_.dfail_total = f.dfail_total;
    rep_.newest_sflags = f.sflags;
    auto rc = reset_count_by_epoch_.find(f.epoch);
    if (rc != reset_count_by_epoch_.end() && f.tpm_reset_count < rc->second) warn("tpm_reset_count_decrease", s);
    reset_count_by_epoch_[f.epoch] = f.tpm_reset_count;
    return std::nullopt;
}

std::optional<Failure> Verifier::check_event_chain_rules(const RecordFields& f, const Hash& h) {
    const std::uint64_t s = f.seq;
    switch (f.dmethod) {
        case kDmKeyed: ++rep_.keyed_records; break;
        case kDmAbsent: ++rep_.absent_records; break;
        case kDmKeyedFailed: ++rep_.failed_records; break;
        default: break;
    }
    if (f.dmethod == kDmKeyedFailed) {
        ++dm4_since_signed_;
        if (!dm4_run_) dm4_run_ = Run{s, s, 0, last_keyed_link_};
        dm4_run_->last = s;
        ++dm4_run_->count;
    }
    if (f.dmethod == kDmKeyed) last_keyed_link_ = h;
    range_digests_.push_back(f.digest);
    if (auto fl = check_forward_contiguity(f)) return fl;
    switch (f.event_code) {
        case code::recv_transfer_end:
            if (f.bytes != 0) {
                if (exact_hi_ && f.subj_first <= *exact_hi_) return Failure{Reason::e_xfer_overlap, s};
                exact_hi_ = std::max(exact_hi_.value_or(0), f.subj_last);
                if (rep_.pruned_start) warn("xfer_overlap_partial_pruned", s);   // F54
            }
            break;
        case code::fault_ack:
            // 6.2: subj_first names an existing FAULT-raising record (A.2 list); reason gap -> it must be a 66.
            if (f.subj_first >= s) return Failure{Reason::e_ack_ref, s};
            if (f.subj_first < first_seq_) {
                warn("ack_ref_unchecked_pruned", s);
            } else {
                auto it = seen_.find(f.subj_first);
                if (it == seen_.end()) return Failure{Reason::e_ack_ref, s};
                const Seen& t = it->second;
                if (f.reason == reason::fault_ack::gap ? t.code != code::chain_gap
                                                       : !codes::is_fault_raising(t.code, t.reason, t.dm4))
                    return Failure{Reason::e_ack_ref, s};
            }
            break;
        case code::tpm_recovered: {
            if (!dm4_run_) {
                if (rep_.pruned_start && f.subj_first < first_seq_) { warn("tpmrec_unchecked_pruned", s); break; }
                return Failure{Reason::e_tpmrec, s};
            }
            const Run r = *dm4_run_;
            if (f.subj_first != r.first || f.subj_last != r.last) {
                if (!(rep_.pruned_start && f.subj_first < first_seq_ && f.subj_last == r.last))
                    return Failure{Reason::e_tpmrec, s};
                warn("tpmrec_partial_pruned", s);
            } else {
                // count == run length, or saturated (2^32-1) with reason saturated; reason saturated iff saturated.
                const bool sat = f.count == kCounterSaturated;
                if (sat != (f.reason == reason::tpm_recovered::saturated)) return Failure{Reason::e_tpmrec, s};
                if (!sat && f.count != r.count) return Failure{Reason::e_tpmrec, s};
                if (!r.anchor) {
                    if (!rep_.pruned_start) return Failure{Reason::e_tpmrec, s};   // no dmethod-1 record before the failure
                    warn("tpmrec_unchecked_pruned", s);
                } else if (f.digest != compute_tpmrec(*r.anchor)) {
                    return Failure{Reason::e_tpmrec, s};
                }
            }
            dm4_run_.reset();
            break;
        }
        case code::chain_gap:
            // a level-4 66 (reason audit_space) follows a 75 level 4 (e_level)
            if (f.reason == reason::chain_gap::audit_space) {
                if (!level_) {
                    if (!rep_.pruned_start) return Failure{Reason::e_level, s};
                    warn("level_unchecked_pruned", s);
                } else if (*level_ != 4) {
                    return Failure{Reason::e_level, s};
                }
                level4_gap_done_ = true;
            }
            break;
        case code::audit_space_level:
            if (f.reason >= reason::audit_space_level::level1 && f.reason <= reason::audit_space_level::level4) {
                const int lvl = f.reason;
                if (!level_ && rep_.pruned_start) {
                    warn("level_unchecked_pruned", s);
                } else {
                    const int cur = level_.value_or(1);
                    if (std::abs(lvl - cur) != 1 || (!level_ && lvl != 2)) return Failure{Reason::e_level, s};
                    if (cur == 4 && lvl < 4 && !level4_gap_done_) return Failure{Reason::e_level, s};
                }
                level_ = lvl;
                level4_gap_done_ = lvl != 4;
            }
            // reason 5 reserve_tampered: FAULT-raising, not a level change.
            break;
        case code::lockdown:
            if (f.reason == reason::lockdown::failed) warn("lockdown_failed", s);
            break;
        case code::commissioning_verified: warn("commissioning", s); break;   // info; NV handle not checkable offline
        default: break;
    }
    return std::nullopt;
}

std::optional<Failure> Verifier::process(const std::uint8_t* p, std::size_t n, std::size_t file_index, bool first_in_file) {
    const std::uint64_t expect = started_ ? next_seq_ : 0;
    // crc (structure + length were checked by the caller)
    if (!crc_ok(p, n)) return Failure{Reason::e_crc, expect};
    const RecordFields f = decode_record(p, n);
    const std::uint64_t s = f.seq;
    if (Reason r = check_record_fields(f); r != Reason::none) return Failure{r, started_ ? expect : s};
    // seq / epoch
    if (!started_) {
        if (f.rec_type == kRtGenesis) {
            if (s != 0) return Failure{Reason::e_seq, s};
            if (!is_zero(f.prev_link)) return Failure{Reason::e_link, s};
            std::memcpy(chain_id_.data(), f.digest.data(), kChainIdSize);
            if (opt_.anchor && opt_.anchor->chain_id != chain_id_) return Failure{Reason::e_unexpected_chain_id, s};
            prev_link_ = f.prev_link;
            fwd_expect_.reset();   // F70: GENESIS resets E
        } else if (opt_.anchor && opt_.anchor->seq >= s) {
            rep_.pruned_start = true;   // chain_id from the anchor; first prev_link accepted (anchored later)
            chain_id_ = opt_.anchor->chain_id;
            prev_link_ = f.prev_link;
            warn("pruned_start", s);
        } else {
            return Failure{Reason::e_no_genesis, s};
        }
        started_ = true;
        first_seq_ = s;
        cur_epoch_ = f.epoch;
        rep_.keyed_mode = !opt_.tag_roots.empty() || !opt_.tag_keys.empty();
    } else {
        if (s != next_seq_) return Failure{first_in_file && file_index > 0 ? Reason::e_file_order : Reason::e_seq, expect};
        if (f.rec_type == kRtGenesis) return Failure{Reason::e_seq, expect};
        if (f.rec_type == kRtEpochStart) {
            // IMMEDIATELY after a CHECKPOINT (A012 F76): else the EVENT digests in between are never aggregated
            if (prev_rec_type_ != kRtCheckpoint) return Failure{Reason::e_epoch_handover, s};
            if (cur_epoch_ == kEpochInvalid - 1 || f.epoch != cur_epoch_ + 1) return Failure{Reason::e_epoch, s};
        } else if (f.epoch != cur_epoch_) {
            return Failure{Reason::e_epoch, s};
        }
    }
    if (first_in_file) {
        std::string hex;
        if (basename_chain_hex(files_[file_index].name, hex) && hex != crypto::to_hex(chain_id_))
            return Failure{Reason::e_unexpected_chain_id, s};
    }
    // dmode
    if (is_signed_type(f.rec_type)) {
        if (f.rec_type == kRtCheckpoint && epoch_dmode_ && f.dmode != *epoch_dmode_) return Failure{Reason::e_dmode, s};
        if (f.rec_type == kRtCheckpoint && !epoch_dmode_) {
            epoch_dmode_ = f.dmode;   // pruned start: learnt from the first CHECKPOINT, then pending records checked
            for (const auto& [ps, pdm] : pending_dmethod_)
                if (auto fl = check_dmethod_vs_dmode(code::recv_group_delivered, pdm, f.dmode, ps)) return fl;
            pending_dmethod_.clear();
        }
    } else {
        const EventSpec* sp = find_event_spec(f.event_code);
        if (sp->digest == Digest::bearing || sp->digest == Digest::optional) {
            if (epoch_dmode_) {
                if (auto fl = check_dmethod_vs_dmode(f.event_code, f.dmethod, *epoch_dmode_, s)) return fl;
            } else if (f.dmethod != kDmNotApplicable) {
                pending_dmethod_.emplace_back(s, f.dmethod);
            }
        }
    }
    // link
    if (!(rep_.pruned_start && s == first_seq_) && f.prev_link != prev_link_) return Failure{Reason::e_link, s};
    const Hash h = compute_link(chain_id_, p, n);
    // tag
    bool tagged = false;
    if (const Hash* k = tag_key(f.epoch)) {
        const Hash t = compute_tag(*k, h, f.digest);
        if (!crypto::ct_equal(t.data(), f.tag.data(), kTagSize)) return Failure{Reason::e_tag, s};
        tagged = true;
    }
    // signature + counters/flags, or EVENT chain rules
    if (is_signed_type(f.rec_type)) {
        if (auto fl = check_signed(f, h)) return fl;
        if (f.rec_type == kRtGenesis || f.rec_type == kRtEpochStart) epoch_dmode_ = f.dmode;
        if (f.rec_type == kRtEpochStart) cur_epoch_ = f.epoch;
    } else {
        if (auto fl = check_event_chain_rules(f, h)) return fl;
        if (!tagged && !first_untagged_after_signed_) first_untagged_after_signed_ = s;
    }
    // writer-reported clock (warnings only)
    if (last_ts_ && f.ts_ms < *last_ts_) warn("ts_regression_writer_reported", s);
    last_ts_ = f.ts_ms;
    if (!rep_.first_ts_ms) rep_.first_ts_ms = f.ts_ms;
    rep_.last_ts_ms = f.ts_ms;
    if (opt_.anchor && opt_.anchor->seq == s) anchor_link_seen_ = h;
    // FAULT-referencable record (69); all earlier verified records are referencable (A011 oracle rule)
    seen_[s] = Seen{f.event_code, f.reason, f.dmethod == kDmKeyedFailed};
    note_epoch(f, tagged);
    if (opt_.collect_records) rep_.records.push_back({f, h, tagged});
    prev_link_ = h;
    prev_rec_type_ = f.rec_type;
    next_seq_ = s + 1;
    rep_.last_verified_seq = s;
    ++rep_.records_verified;
    return std::nullopt;
}

std::optional<Failure> Verifier::check_forward_contiguity(const RecordFields& f) {
    // DESIGN v0.3.4 6.2 (A011 F70). Records 16, 17, 72 advance E = subj_last + 1; 68, 22 reason reseed and
    // GENESIS reset E; E is unknown at the first record of a verification. A normal record not starting at
    // E -> warning fwd_seq_jump only. The ONLY FAIL: a level-4 66 (reason audit_space) whose subj_first is
    // above a known E (lower bound, e_gap_range). That 66 then sets E = subj_last + 1 (as in
    // tests/spec/layout_v0_3_4.py contiguity() for reason 3).
    switch (f.event_code) {
        case code::recv_coverage: fwd_expect_.reset(); break;
        case code::recv_transfer_start:
            if (f.reason == reason::recv_transfer_start::reseed) fwd_expect_.reset();
            break;
        case code::chain_gap:
            // Only the level-4 66 (reason audit_space) takes part (6.2 "LOWER BOUND for 66: a level-4 66 ...");
            // it then moves E past the hole it covers (layout_v0_3_4.py case (66,3,32,49),(16,50..60) -> no warning).
            // Other 66 reasons neither FAIL nor move E (text lists only 16/17/72 as advancing E). Open question.
            if (f.reason == reason::chain_gap::audit_space) {
                if (fwd_expect_ && f.subj_first > *fwd_expect_) return Failure{Reason::e_gap_range, f.seq};
                fwd_expect_ = f.subj_last + 1;
            }
            break;
        case code::recv_group_delivered:
        case code::recv_void:
        case code::recv_groups_compacted:
            if (fwd_expect_ && f.subj_first != *fwd_expect_) warn("fwd_seq_jump", f.seq);
            fwd_expect_ = f.subj_last + 1;
            break;
        default: break;
    }
    return std::nullopt;
}

std::optional<Failure> Verifier::check_dagg(const RecordFields& f) {
    // DESIGN v0.3.4 4.3 (A011 F71), the only rule: SHA-256(DS_AGG || digest of EVERY EVENT in
    // (prev signed seq, this seq], seq order, zeros included), every dmode.
    if (!dagg_range_complete_) {   // pruned start: the range begins before the first record we have
        warn("dagg_unchecked_pruned", f.seq);
        return std::nullopt;
    }
    if (compute_dagg(range_digests_) != f.d_agg) return Failure{Reason::e_dagg, f.seq};
    return std::nullopt;
}

Report Verifier::run() {
    rep_.anchor_given = opt_.anchor.has_value();
    if (opt_.anchor) rep_.anchor_seq = opt_.anchor->seq;
    auto finish_io = [&](std::string why) {
        rep_.outcome = Outcome{};
        rep_.outcome.io_or_usage_error = true;
        rep_.io_error = std::move(why);
        rep_.exit = exit_code_for(rep_.outcome);
        return rep_;
    };
    if (!opt_.pubkeys) return finish_io("--pubkeys is required (the only key source)");
    if (files_.empty()) return finish_io("no chain files");
    for (const auto& f : files_)
        if (f.bytes.size() > kMaxChainFileBytes) return finish_io("chain file larger than 64 MiB + 316 B");

    std::optional<Failure> fail;
    for (std::size_t fi = 0; fi < files_.size() && !fail; ++fi) {
        if (fi > 0 && !(files_[fi - 1].name < files_[fi].name)) { fail = Failure{Reason::e_file_order, next_seq_}; break; }
        const auto& b = files_[fi].bytes;
        const bool last_file = fi + 1 == files_.size();
        if (b.empty() && !last_file) { fail = Failure{Reason::e_short, next_seq_}; break; }
        std::size_t off = 0;
        bool first = true;
        while (off < b.size()) {
            const std::uint8_t* p = b.data() + off;
            const std::size_t rem = b.size() - off;
            // 5.3 torn-tail rule (newest file only)
            if (rem < kMinRecordSize) {
                if (last_file) { rep_.torn_bytes = rem; break; }
                fail = Failure{Reason::e_short, started_ ? next_seq_ : 0};
                break;
            }
            const HeaderParse hp = parse_header(p, rem);
            if (hp.reason != Reason::none) { fail = Failure{hp.reason, started_ ? next_seq_ : 0}; break; }
            if (rem < hp.rec_len) {
                if (last_file) { rep_.torn_bytes = rem; break; }
                fail = Failure{Reason::e_short, started_ ? next_seq_ : 0};
                break;
            }
            fail = process(p, hp.rec_len, fi, first);
            if (fail) break;
            first = false;
            off += hp.rec_len;
        }
    }
    if (!fail && !started_) fail = Failure{Reason::e_no_genesis, 0};
    if (!fail && opt_.anchor) {
        if (!rep_.last_verified_seq || *rep_.last_verified_seq < opt_.anchor->seq) {
            fail = Failure{Reason::e_behind_anchor, next_seq_};
        } else if (!anchor_link_seen_ || *anchor_link_seen_ != opt_.anchor->link) {
            fail = Failure{Reason::e_anchor_mismatch, opt_.anchor->seq};
        } else {
            rep_.anchor_matched = true;
            rep_.records_after_anchor = *rep_.last_verified_seq - opt_.anchor->seq;
        }
    }
    rep_.outcome = Outcome{};
    if (fail) {
        rep_.outcome.fail = true;
        rep_.reason = fail->reason;
        rep_.first_bad_seq = fail->seq;
    } else {
        if (level_ && *level_ == 4 && !level4_gap_done_) warn("gap_open", next_seq_ ? next_seq_ - 1 : 0);
        if (!pending_dmethod_.empty()) warn("dmode_unknown_pruned", pending_dmethod_.front().first);
        rep_.outcome.recovered = rep_.recoveries_total > 0;
        rep_.outcome.gap = rep_.gaps_total > 0;
        rep_.outcome.successor = (rep_.newest_sflags & kSflagSuccessor) != 0;
        rep_.outcome.digest_failed = (rep_.newest_sflags & kSflagDigestFailed) != 0 || rep_.dfail_total > 0;
        if (first_untagged_after_signed_) {   // records after the last signature without a verified tag
            rep_.outcome.tail_unverified = true;
            rep_.tail_unverified_from = first_untagged_after_signed_;
        }
        rep_.outcome.unanchored = !opt_.anchor;
        rep_.outcome.torn_tail = rep_.torn_bytes > 0;
    }
    rep_.last_signed_seq = last_signed_;
    rep_.exit = exit_code_for(rep_.outcome);
    return rep_;
}

}  // namespace

Report verify_chain(const std::vector<ChainFile>& files, const VerifyOptions& opt) {
    Verifier v(files, opt);
    return v.run();
}

Report device_self_check(const std::vector<ChainFile>& segments, const PubKeyList& pubkeys,
                         const std::map<std::uint32_t, Hash>& epoch_tag_keys, const std::optional<Anchor>& anchor) {
    VerifyOptions o;
    o.pubkeys = &pubkeys;
    o.tag_keys = epoch_tag_keys;
    o.anchor = anchor;
    return verify_chain(segments, o);
}

}  // namespace ct01::audit
