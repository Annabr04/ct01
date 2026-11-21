#include "ct01/audit_inputs.hpp"

namespace ct01::audit {

const PubKeyEntry* PubKeyList::find(std::uint32_t epoch) const {
    for (const auto& e : entries)
        if (e.epoch == epoch) return &e;
    return nullptr;
}

bool parse_u64(std::string_view s, std::uint64_t& out) {
    if (s.empty() || s.size() > 20) return false;
    std::uint64_t v = 0;
    for (char c : s) {
        if (c < '0' || c > '9') return false;
        const std::uint64_t d = static_cast<std::uint64_t>(c - '0');
        if (v > (UINT64_MAX - d) / 10) return false;
        v = v * 10 + d;
    }
    if (s.size() > 1 && s[0] == '0') return false;   // canonical decimal only
    out = v;
    return true;
}

namespace {
std::string_view trim(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t' || s.front() == '\r')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}
bool take_kv(std::string_view& rest, std::string_view key, std::string_view& val) {
    rest = trim(rest);
    if (rest.substr(0, key.size()) != key || rest.size() <= key.size() || rest[key.size()] != '=') return false;
    rest.remove_prefix(key.size() + 1);
    const std::size_t sp = rest.find_first_of(" \t");
    val = rest.substr(0, sp);
    rest = sp == std::string_view::npos ? std::string_view{} : rest.substr(sp);
    return !val.empty();
}
}  // namespace

std::optional<PubKeyList> parse_pubkeys(std::string_view text, std::string& error) {
    if (text.size() > kMaxPubKeysFileBytes) { error = "pubkeys file too large"; return std::nullopt; }
    PubKeyList out;
    bool header = false;
    std::size_t lineno = 0;
    while (!text.empty()) {
        const std::size_t nl = text.find('\n');
        std::string_view line = trim(text.substr(0, nl));
        text = nl == std::string_view::npos ? std::string_view{} : text.substr(nl + 1);
        ++lineno;
        const std::string where = "pubkeys line " + std::to_string(lineno) + ": ";
        if (line.empty() || line[0] == '#') continue;
        for (char c : line)
            if (static_cast<unsigned char>(c) < 0x20 && c != '\t') { error = where + "control character"; return std::nullopt; }
        if (!header) {
            if (line != "ct01-audit-pubkeys v1") { error = where + "missing header 'ct01-audit-pubkeys v1'"; return std::nullopt; }
            header = true;
            continue;
        }
        std::string_view rest = line, v_epoch, v_first, v_last, v_id, v_pub;
        if (!take_kv(rest, "epoch", v_epoch) || !take_kv(rest, "first", v_first) || !take_kv(rest, "last", v_last) ||
            !take_kv(rest, "key_id", v_id) || !take_kv(rest, "pub", v_pub) || !trim(rest).empty()) {
            error = where + "expected 'epoch= first= last= key_id= pub='";
            return std::nullopt;
        }
        std::uint64_t ep = 0, first = 0, last = UINT64_MAX;
        if (!parse_u64(v_epoch, ep) || ep >= layout::kEpochInvalid) { error = where + "bad epoch"; return std::nullopt; }
        if (!parse_u64(v_first, first)) { error = where + "bad first"; return std::nullopt; }
        if (v_last != "open" && !parse_u64(v_last, last)) { error = where + "bad last"; return std::nullopt; }
        if (first > last) { error = where + "first > last"; return std::nullopt; }
        layout::Hash id{};
        crypto::Point65 pt{};
        const bool pinned = v_id != "unpinned";
        if (pinned && !crypto::from_hex(v_id, id.data(), id.size())) { error = where + "bad key_id"; return std::nullopt; }
        if (!crypto::from_hex(v_pub, pt.data(), pt.size())) { error = where + "bad pub"; return std::nullopt; }
        auto key = crypto::P256PublicKey::from_sec1(pt);
        if (!key) { error = where + "pub is not a valid P-256 point"; return std::nullopt; }
        if (!out.entries.empty()) {
            const auto& prev = out.entries.back();
            if (ep <= prev.epoch) { error = where + "epochs must strictly increase"; return std::nullopt; }
            // ranges may share at most the EPOCH_START seq (signed by S_e, epoch e+1)
            if (prev.last == UINT64_MAX || first < prev.last) { error = where + "overlapping pinned ranges"; return std::nullopt; }
        }
        if (out.entries.size() >= kMaxPubKeyEntries) { error = where + "too many keys"; return std::nullopt; }
        out.entries.push_back(PubKeyEntry{static_cast<std::uint32_t>(ep), first, last, id, pinned, std::move(*key)});
    }
    if (!header) { error = "pubkeys: empty file"; return std::nullopt; }
    if (out.entries.empty()) { error = "pubkeys: no keys"; return std::nullopt; }
    return out;
}

std::optional<Anchor> parse_anchor(std::string_view s) {
    const std::size_t a = s.find(':');
    if (a == std::string_view::npos) return std::nullopt;
    const std::size_t b = s.find(':', a + 1);
    if (b == std::string_view::npos) return std::nullopt;
    Anchor out;
    if (!parse_u64(s.substr(0, a), out.seq) || out.seq == layout::kSeqInvalid) return std::nullopt;
    if (!crypto::from_hex(s.substr(a + 1, b - a - 1), out.link.data(), out.link.size())) return std::nullopt;
    if (!crypto::from_hex(s.substr(b + 1), out.chain_id.data(), out.chain_id.size())) return std::nullopt;
    return out;
}

std::optional<std::uint32_t> parse_epoch_number(std::string_view s) {
    std::uint64_t v = 0;
    if (!parse_u64(s, v) || v >= layout::kEpochInvalid) return std::nullopt;
    return static_cast<std::uint32_t>(v);
}

std::optional<layout::Hash> parse_tag_root(std::string_view content) {
    if (!content.empty() && content.back() == '\n') content.remove_suffix(1);
    layout::Hash h{};
    if (!crypto::from_hex(content, h.data(), h.size())) return std::nullopt;
    return h;
}

}  // namespace ct01::audit
