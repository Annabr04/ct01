// Standalone driver for libFuzzer-style targets, so they build and run with
// any compiler (GCC + ASan/UBSan here) and under CTest.
//   driver [--random N] [--seed S] [--max-len M] [--seconds T] FILE_OR_DIR...
// Replays every file given (directories: every regular file inside, sorted),
// then runs N (or until T seconds) seeded random inputs: half mutations of the
// loaded corpus (byte flips, u16 tweaks, splices, truncation/extension), half
// fresh random bytes. Deterministic for a given seed and corpus.
#include <algorithm>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size);
// Optional per-target counter of accepted inputs (weak: absent for other targets).
extern "C" unsigned long long fuzz_target_accepted __attribute__((weak));

namespace {
struct Rng {  // splitmix64
    std::uint64_t s;
    std::uint64_t next() {
        std::uint64_t z = (s += 0x9E3779B97F4A7C15ull);
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
        return z ^ (z >> 31);
    }
    std::size_t below(std::size_t n) { return n ? static_cast<std::size_t>(next() % n) : 0; }
};
using Buf = std::vector<std::uint8_t>;

Buf read_file(const std::filesystem::path& p) {
    std::ifstream f(p, std::ios::binary);
    return Buf(std::istreambuf_iterator<char>(f), std::istreambuf_iterator<char>());
}

void run(const Buf& b) {
    // Copy into an exact-size heap buffer so ASan catches any over-read.
    std::uint8_t* p = b.empty() ? nullptr : new std::uint8_t[b.size()];
    if (p) std::memcpy(p, b.data(), b.size());
    LLVMFuzzerTestOneInput(p, b.size());
    delete[] p;
}

void mutate(Buf& b, Rng& r, std::size_t max_len, const std::vector<Buf>& corpus) {
    const int n = 1 + static_cast<int>(r.below(6));
    for (int i = 0; i < n; ++i) {
        switch (r.below(7)) {
            case 0: if (!b.empty()) b[r.below(b.size())] ^= static_cast<std::uint8_t>(1u << r.below(8)); break;
            case 1: if (!b.empty()) b[r.below(b.size())] = static_cast<std::uint8_t>(r.next()); break;
            case 2: if (b.size() > 4) { const std::size_t at = 3 + 2 * r.below((b.size() - 3) / 2);
                        if (at + 1 < b.size()) { unsigned v = b[at] | (b[at + 1] << 8);
                            v += static_cast<unsigned>(r.below(5)) - 2u; b[at] = static_cast<std::uint8_t>(v);
                            b[at + 1] = static_cast<std::uint8_t>(v >> 8); } } break;
            case 3: if (!b.empty()) b.resize(r.below(b.size() + 1)); break;
            case 4: if (b.size() < max_len) b.push_back(static_cast<std::uint8_t>(r.next())); break;
            case 5: if (!corpus.empty()) { const Buf& o = corpus[r.below(corpus.size())];
                        if (!o.empty() && !b.empty()) { const std::size_t at = r.below(b.size());
                            const std::size_t len = std::min(o.size(), b.size() - at);
                            std::memcpy(b.data() + at, o.data(), len); } } break;
            default: if (!b.empty()) b[0] = static_cast<std::uint8_t>(9 + r.below(4)); break;  // valid R
        }
    }
    if (b.size() > max_len) b.resize(max_len);
}
}  // namespace

int main(int argc, char** argv) {
    std::uint64_t iterations = 0, seed = 1, max_len = 3 + 2 * 256 + 8;
    double seconds = 0;
    std::vector<std::filesystem::path> files;
    for (int i = 1; i < argc; ++i) {
        const std::string a = argv[i];
        auto val = [&]() -> const char* {
            if (i + 1 >= argc) { std::fprintf(stderr, "missing value for %s\n", a.c_str()); std::exit(2); }
            return argv[++i];
        };
        if (a == "--random") iterations = std::strtoull(val(), nullptr, 10);
        else if (a == "--seed") seed = std::strtoull(val(), nullptr, 10);
        else if (a == "--max-len") max_len = std::strtoull(val(), nullptr, 10);
        else if (a == "--seconds") seconds = std::strtod(val(), nullptr);
        else if (std::filesystem::is_directory(a)) {
            std::vector<std::filesystem::path> d;
            for (const auto& e : std::filesystem::directory_iterator(a))
                if (e.is_regular_file()) d.push_back(e.path());
            std::sort(d.begin(), d.end());
            files.insert(files.end(), d.begin(), d.end());
        } else if (std::filesystem::is_regular_file(a)) files.push_back(a);
        else { std::fprintf(stderr, "no such file or directory: %s\n", a.c_str()); return 2; }
    }
    std::vector<Buf> corpus;
    for (const auto& f : files) corpus.push_back(read_file(f));
    for (const auto& b : corpus) run(b);
    std::printf("replayed %zu corpus files\n", corpus.size());

    Rng r{seed};
    const auto t0 = std::chrono::steady_clock::now();
    std::uint64_t done = 0;
    for (;; ++done) {
        if (seconds > 0) {
            if ((done & 1023) == 0 &&
                std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count() >= seconds) break;
        } else if (done >= iterations) break;
        Buf b;
        if (!corpus.empty() && r.below(2) == 0) {
            b = corpus[r.below(corpus.size())];
            mutate(b, r, max_len, corpus);
        } else {
            b.resize(r.below(max_len + 1));
            for (auto& x : b) x = static_cast<std::uint8_t>(r.next());
            if (!b.empty() && r.below(2) == 0) b[0] = static_cast<std::uint8_t>(9 + r.below(4));
            if (b.size() > 2 && r.below(2) == 0) b[2] |= 2;  // repair mode
        }
        run(b);
    }
    const double el = std::chrono::duration<double>(std::chrono::steady_clock::now() - t0).count();
    std::printf("random inputs: %llu (seed %llu) in %.1f s, 0 findings",
                static_cast<unsigned long long>(done), static_cast<unsigned long long>(seed), el);
    if (&fuzz_target_accepted != nullptr) std::printf("; accepted (corpus+random): %llu", fuzz_target_accepted);
    std::printf("\n");
    return 0;
}
