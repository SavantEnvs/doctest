// Fuzz doctest's command-line surface: Context::applyCommandLine() + Context::run().
// Every doctest-built test binary parses argv with this code: option parsing (-tc=, -sf=, -ob=,
// -rs=, --first/--last, -r=, list/count/help modes), comma-separated filters with wildcard matching,
// test ordering, subcase filtering and the console/xml/junit reporters.
//
// Input: split on '\n' and NUL into argv[1..] (argv[0] is fixed). The last piece is also handed to
// the TEST_CASE bodies below as data (SUBCASE name, INFO, CHECK operand).
// Per-input state: a fresh Context per input; output goes to an in-memory discard stream (setCout),
// so `--out=` from the input cannot write files. Test registration is static and read-only.
#define DOCTEST_CONFIG_IMPLEMENT
#define DOCTEST_CONFIG_NO_POSIX_SIGNALS // keep ASan/libFuzzer in charge of fatal signals
#include "doctest.h"

#include <cstdint>
#include <sstream>
#include <string>
#include <vector>

static std::string g_data;

TEST_SUITE("alpha") {
    TEST_CASE("first case") {
        CHECK(g_data.size() < 100000);
        SUBCASE("sub one") { CHECK(1 == 1); }
        SUBCASE("sub two") {
            SUBCASE("nested") { CHECK_FALSE(g_data == "nested"); }
        }
    }
    TEST_CASE("data driven" * doctest::description("uses the input")) {
        INFO("data: ", doctest::String(g_data.data(), static_cast<doctest::String::size_type>(g_data.size())));
        SUBCASE(doctest::String(g_data.c_str()).c_str()) { CHECK(g_data.find('x') == std::string::npos); }
        CHECK_MESSAGE(g_data.size() % 2 == 0, "odd length ", g_data.size());
    }
}

TEST_SUITE("beta" * doctest::description("second suite")) {
    TEST_CASE("may fail" * doctest::may_fail()) { CHECK(g_data.empty()); }
    TEST_CASE("should fail" * doctest::should_fail()) { CHECK(g_data == "never"); }
    TEST_CASE("expected failures" * doctest::expected_failures(1)) { CHECK(g_data.size() == 7); }
    TEST_CASE("skipped" * doctest::skip()) { CHECK(false); }
}

TEST_CASE_TEMPLATE("templated", T, int, char, double) {
    T v = static_cast<T>(g_data.size() & 0x7f);
    CHECK(v == static_cast<T>(g_data.size() & 0x7f));
}

TEST_CASE("approx and require") {
    double d = static_cast<double>(g_data.size()) / 3.0;
    CHECK(d == doctest::Approx(static_cast<double>(g_data.size()) / 3.0));
    WARN(g_data.size() != 3);
    REQUIRE(g_data != "stop");
    CHECK(true);
}

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    std::vector<std::string> pieces;
    std::string cur;
    for (size_t i = 0; i < size; ++i) {
        char c = static_cast<char>(data[i]);
        if (c == '\n' || c == '\0') {
            pieces.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    pieces.push_back(cur);
    if (pieces.size() > 64)
        pieces.resize(64);
    g_data = pieces.back();

    std::vector<const char *> argv;
    argv.push_back("fuzz_cli");
    for (const auto &p : pieces)
        argv.push_back(p.c_str());

    std::ostringstream sink;
    doctest::Context ctx;
    ctx.applyCommandLine(static_cast<int>(argv.size()), argv.data());
    ctx.setOption("no-breaks", true);
    ctx.setCout(&sink);
    ctx.run();
    return 0;
}
