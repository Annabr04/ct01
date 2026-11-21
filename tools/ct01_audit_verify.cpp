// ct01_audit_verify: offline, read-only audit_chain verifier (DESIGN v0.3.4 6.2).
//   ct01_audit_verify --pubkeys FILE [--anchor SEQ:LINK:CHAIN_ID] [--epoch-key E:FILE]... [--export-jsonl] CHAIN_FILE...
// Keys come ONLY from --pubkeys (no environment variables, no default paths, no embedded keys).
// stdout: one JSON report line (with --export-jsonl: one JSON line per verified record first, then the
// report). NO paths in stdout; paths appear on stderr only. Exit codes 0-6 (7-9 reserved, never emitted).
#include "ct01/audit_inputs.hpp"
#include "ct01/audit_json.hpp"
#include "ct01/audit_verify.hpp"

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <string>
#include <sys/stat.h>
#include <unistd.h>
#include <vector>

using namespace ct01::audit;

namespace {

bool read_regular(const std::string& path, std::size_t limit, std::vector<std::uint8_t>& out, std::string& err) {
    const int fd = ::open(path.c_str(), O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0) { err = path + ": " + std::strerror(errno); return false; }
    struct stat st {};
    if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) { ::close(fd); err = path + ": not a regular file"; return false; }
    if (static_cast<std::uint64_t>(st.st_size) > limit) { ::close(fd); err = path + ": file too large"; return false; }
    out.resize(static_cast<std::size_t>(st.st_size));
    std::size_t got = 0;
    while (got < out.size()) {
        const ssize_t n = ::read(fd, out.data() + got, out.size() - got);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ::close(fd); err = path + ": read error"; return false; }
        got += static_cast<std::size_t>(n);
    }
    char extra;
    if (::read(fd, &extra, 1) != 0) { ::close(fd); err = path + ": file changed while reading"; return false; }
    ::close(fd);
    return true;
}

std::string basename_of(const std::string& p) {
    const auto i = p.find_last_of('/');
    return i == std::string::npos ? p : p.substr(i + 1);
}

int usage_exit(const std::string& msg) {
    std::fprintf(stderr, "ct01_audit_verify: %s\n", msg.c_str());
    std::fprintf(stderr, "usage: ct01_audit_verify --pubkeys FILE [--anchor SEQ:LINK:CHAIN_ID] [--epoch-key E:FILE]... "
                         "[--export-jsonl] CHAIN_FILE...\n");
    Report r;   // exit 1 report, no paths
    r.outcome.io_or_usage_error = true;
    r.exit = exit_code_for(r.outcome);
    std::printf("%s\n", report_json(r).c_str());
    return r.exit;
}

}  // namespace

int main(int argc, char** argv) {
    std::optional<std::string> pubkeys_path;
    std::optional<Anchor> anchor;
    std::map<std::uint32_t, Hash> tag_roots;
    bool export_jsonl = false;
    std::vector<std::string> files;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto need = [&](const char* what) -> std::optional<std::string> {
            if (i + 1 >= argc) return std::nullopt;
            (void)what;
            return std::string(argv[++i]);
        };
        if (a == "--pubkeys") {
            auto v = need("FILE");
            if (!v || pubkeys_path) return usage_exit("--pubkeys needs exactly one FILE");
            pubkeys_path = v;
        } else if (a == "--anchor") {
            auto v = need("SEQ:LINK:CHAIN_ID");
            if (!v || anchor) return usage_exit("--anchor needs exactly one SEQ:LINK:CHAIN_ID");
            anchor = parse_anchor(*v);
            if (!anchor) return usage_exit("malformed --anchor");
        } else if (a == "--epoch-key") {
            auto v = need("E:FILE");
            if (!v) return usage_exit("--epoch-key needs E:FILE");
            const auto c = v->find(':');
            if (c == std::string::npos) return usage_exit("--epoch-key needs E:FILE");
            auto e = parse_epoch_number(v->substr(0, c));
            if (!e || tag_roots.count(*e)) return usage_exit("bad or duplicate --epoch-key epoch");
            std::vector<std::uint8_t> raw;
            std::string err;
            if (!read_regular(v->substr(c + 1), 4096, raw, err)) return usage_exit(err);
            auto root = parse_tag_root(std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()));
            if (!root) return usage_exit("malformed --epoch-key file (64 hex expected)");
            tag_roots[*e] = *root;
        } else if (a == "--export-jsonl") {
            export_jsonl = true;
        } else if (a == "--checkpoints" || a == "--allowlist") {
            return usage_exit(a + " is not implemented in M1 (M3/M4); refusing rather than ignoring it");
        } else if (a == "--") {
            for (++i; i < argc; ++i) files.emplace_back(argv[i]);
        } else if (a.size() > 1 && a[0] == '-') {
            return usage_exit("unknown option " + a);
        } else {
            files.push_back(a);
        }
    }
    if (!pubkeys_path) return usage_exit("--pubkeys is required (the only key source)");
    if (files.empty()) return usage_exit("no chain files");

    std::vector<std::uint8_t> raw;
    std::string err;
    if (!read_regular(*pubkeys_path, kMaxPubKeysFileBytes, raw, err)) return usage_exit(err);
    auto keys = parse_pubkeys(std::string_view(reinterpret_cast<const char*>(raw.data()), raw.size()), err);
    if (!keys) return usage_exit("--pubkeys: " + err);

    std::vector<ChainFile> chain;
    for (const auto& p : files) {
        ChainFile cf;
        cf.name = basename_of(p);
        if (!read_regular(p, ct01::audit::layout::kMaxChainFileBytes, cf.bytes, err)) return usage_exit(err);
        chain.push_back(std::move(cf));
    }
    if (!tag_roots.empty()) std::fprintf(stderr, "ct01_audit_verify: --epoch-key is TEST-ONLY / on-device (Q2: no escrow)\n");

    VerifyOptions o;
    o.pubkeys = &*keys;
    o.anchor = anchor;
    o.tag_roots = tag_roots;
    o.collect_records = export_jsonl;
    const Report r = verify_chain(chain, o);
    if (export_jsonl)
        for (const auto& v : r.records) std::printf("%s\n", record_jsonl(v).c_str());
    std::printf("%s\n", report_json(r).c_str());
    if (r.absent_records) std::fprintf(stderr, "DIGEST ABSENT %llu\n", static_cast<unsigned long long>(r.absent_records));
    if (r.failed_records) std::fprintf(stderr, "DIGEST FAILED %llu\n", static_cast<unsigned long long>(r.failed_records));
    if (r.outcome.fail)
        std::fprintf(stderr, "FAIL %s at seq %llu\n", std::string(reason_name(r.reason)).c_str(),
                     static_cast<unsigned long long>(r.first_bad_seq.value_or(0)));
    if (!r.io_error.empty()) std::fprintf(stderr, "ct01_audit_verify: %s\n", r.io_error.c_str());
    return r.exit;
}
