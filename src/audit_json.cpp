#include "ct01/audit_json.hpp"

#include "ct01/audit_crypto.hpp"

namespace ct01::audit {

using namespace layout;

namespace {
class Obj {
public:
    Obj& raw(const char* k, const std::string& v) { key(k); s_ += v; return *this; }
    Obj& str(const char* k, std::string_view v) {   // values are fixed ASCII enum names only
        key(k);
        s_ += '"';
        for (char c : v) {
            if (c == '"' || c == '\\') s_ += '\\';
            if (static_cast<unsigned char>(c) >= 0x20) s_ += c;
        }
        s_ += '"';
        return *this;
    }
    Obj& u64(const char* k, std::uint64_t v) { return str(k, std::to_string(v)); }
    Obj& num(const char* k, std::uint64_t v) { return raw(k, std::to_string(v)); }
    Obj& boolean(const char* k, bool v) { return raw(k, v ? "true" : "false"); }
    Obj& opt_u64(const char* k, const std::optional<std::uint64_t>& v) { return v ? u64(k, *v) : raw(k, "null"); }
    std::string done() { return s_ + "}"; }
private:
    void key(const char* k) { s_ += first_ ? "" : ","; first_ = false; s_ += '"'; s_ += k; s_ += "\":"; }
    std::string s_ = "{";
    bool first_ = true;
};

std::string_view rec_type_name(std::uint8_t rt) {
    switch (rt) {
        case kRtGenesis: return "genesis";
        case kRtEvent: return "event";
        case kRtCheckpoint: return "checkpoint";
        case kRtEpochStart: return "epoch_start";
        default: return "unknown";
    }
}
std::string_view dmethod_name(std::uint8_t d) {
    switch (d) {
        case kDmKeyed: return "keyed";
        case kDmAbsent: return "absent";
        case kDmNotApplicable: return "not_applicable";
        case kDmKeyedFailed: return "keyed_failed";
        default: return "unknown";
    }
}
std::string_view dmode_name(std::uint8_t d) { return d == kDmodeKeyed ? "keyed" : d == kDmodeAbsent ? "absent" : d == 0 ? "none" : "unknown"; }
std::string_view actor_name(std::uint8_t a) {
    switch (a) {
        case kActorNone: return "none";
        case kActorSystem: return "system_service";
        case kActorReceiver: return "receiver_service";
        case kActorStaff: return "staff_operator";
        case kActorSource: return "source_device";
        default: return "unknown";
    }
}
}  // namespace

std::string report_json(const Report& r) {
    Obj o;
    o.str("result", result_name(r.exit)).num("exit", static_cast<std::uint64_t>(r.exit));
    std::string q = "[";
    for (const auto& x : r.qualifiers()) q += (q.size() > 1 ? ",\"" : "\"") + x + "\"";
    o.raw("qualifiers", q + "]");
    if (!r.anchor_given) o.str("anchor", "none");
    else o.raw("anchor", Obj().u64("seq", r.anchor_seq).boolean("matched", r.anchor_matched).done());
    o.opt_u64("records_after_anchor", r.records_after_anchor);
    o.str("reason", r.outcome.fail ? reason_name(r.reason) : std::string_view("none"));
    o.num("reason_code", r.outcome.fail ? static_cast<std::uint64_t>(r.reason) : 0);   // A.1 number (0 = e_none)
    o.opt_u64("first_bad_seq", r.first_bad_seq).opt_u64("last_verified_seq", r.last_verified_seq);
    o.opt_u64("last_signed_seq", r.last_signed_seq).opt_u64("tail_unverified_from", r.tail_unverified_from);
    o.u64("torn_bytes", r.torn_bytes);
    o.u64("recoveries_total", r.recoveries_total).u64("gaps_total", r.gaps_total).u64("dfail_total", r.dfail_total);
    o.boolean("successor_lineage", (r.newest_sflags & kSflagSuccessor) != 0);
    o.boolean("digest_failed_flag", (r.newest_sflags & kSflagDigestFailed) != 0);
    o.str("mode", r.keyed_mode ? "keyed_test_only" : "public");
    o.boolean("pruned_start", r.pruned_start).u64("records_verified", r.records_verified);
    o.raw("clock", Obj().str("source", "writer_reported").opt_u64("first_ts_ms", r.first_ts_ms)
                       .opt_u64("last_ts_ms", r.last_ts_ms).done());
    std::string_view mode = "none";
    bool any_keyed = false, any_absent = false, any_unknown = false;
    for (const auto& e : r.epochs) {
        any_keyed |= e.dmode == kDmodeKeyed;
        any_absent |= e.dmode == kDmodeAbsent;
        any_unknown |= e.dmode == 0;
    }
    if (any_keyed && any_absent) mode = "mixed";
    else if (any_keyed) mode = "keyed";
    else if (any_absent) mode = "absent";
    else if (any_unknown) mode = "unknown";
    o.raw("digest", Obj().str("mode", mode).u64("keyed_records", r.keyed_records).u64("absent_records", r.absent_records)
                        .u64("failed_records", r.failed_records).boolean("verified_against_data", false).done());
    o.str("allowlist", "unchecked");
    std::string ep = "[";
    for (const auto& e : r.epochs) {
        if (ep.size() > 1) ep += ",";
        ep += Obj().num("epoch", e.epoch).str("dmode", dmode_name(e.dmode)).u64("first_seq", e.first_seq)
                  .u64("last_seq", e.last_seq).u64("records", e.records).boolean("tags_checked", e.tag_checked).done();
    }
    o.raw("epochs", ep + "]").u64("epochs_total", r.epochs_total);
    std::string w = "[";
    for (const auto& x : r.warnings) {
        if (w.size() > 1) w += ",";
        w += Obj().str("code", x.code).u64("seq", x.seq).done();
    }
    o.raw("warnings", w + "]").u64("warnings_total", r.warnings_total);
    return o.done();
}

std::string record_jsonl(const VerifiedRecord& v) {
    const RecordFields& f = v.f;
    const EventSpec* s = find_event_spec(f.event_code);
    Obj o;
    o.str("type", "record").u64("seq", f.seq).str("rec_type", rec_type_name(f.rec_type));
    o.str("event", s ? s->name : std::string_view("unknown")).num("epoch", f.epoch);
    // reason: frozen per-code number (DESIGN v0.3.4 Appendix A.2) + its fixed name.
    o.num("reason", f.reason).str("reason_name", codes::reason_value_name(f.event_code, f.reason));
    o.str("actor_class", actor_name(f.actor_class)).num("actor_uid", f.actor_uid);
    o.str("dmethod", dmethod_name(f.dmethod)).str("dmode", dmode_name(f.dmode));
    o.num("len_bucket", f.len_bucket).num("sflags", f.sflags);
    o.u64("ts_ms_writer_reported", f.ts_ms).u64("mono_ms_writer_reported", f.mono_ms);
    o.u64("subj_first", f.subj_first).u64("subj_last", f.subj_last);
    // GENESIS count = predecessor FAIL reason (A.1 e_* number; non-zero only for GENESIS reason 3).
    if (f.rec_type == kRtGenesis) {
        o.num("pred_fail_reason", f.count)
            .str("pred_fail_reason_name", f.count < kReasonNames.size() ? kReasonNames[f.count] : std::string_view("unknown"));
    } else {
        o.u64("count", f.count);
    }
    o.u64("bytes", f.bytes);
    o.str("prev_link", crypto::to_hex(f.prev_link)).str("link", crypto::to_hex(v.link));
    if (is_signed_type(f.rec_type)) {
        o.u64("nv_export", f.nv_export).u64("tpm_clock_ms_writer_reported", f.tpm_clock_ms);
        o.u64("tpm_reset_count", f.tpm_reset_count).u64("tpm_restart_count", f.tpm_restart_count);
        o.u64("recoveries_total", f.recoveries_total).u64("gaps_total", f.gaps_total).u64("dfail_total", f.dfail_total);
        if (f.rec_type == kRtCheckpoint) o.str("d_agg", crypto::to_hex(f.d_agg));   // d_agg only in checkpoints (Q5)
        o.str("sig", crypto::to_hex(f.sig));
    }
    o.boolean("tag_verified", v.tag_verified);
    return o.done();
}

}  // namespace ct01::audit
