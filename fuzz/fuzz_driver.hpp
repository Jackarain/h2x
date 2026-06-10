//
// fuzz_driver.hpp
// ~~~~~~~~~~~~~~~~
//
// Copyright (c) 2026 Jack (jack dot wgm at gmail dot com)
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
// Provides a standalone main() for running fuzz targets against a corpus
// directory when libFuzzer is not available (e.g., macOS Xcode without the
// fuzzer runtime library).
//
// Compile with -DSTANDALONE_FUZZER to use this driver instead of libFuzzer.
//
// Usage:
//   ./fuzz_target corpus_dir/   # run all seeds
//   ./fuzz_target single.bin    # run a single file
//

#ifndef H2X_FUZZ_DRIVER_HPP
#define H2X_FUZZ_DRIVER_HPP

#ifdef STANDALONE_FUZZER

#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <vector>
#include <string>
#include <iostream>

// The fuzz target must define this function.
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

namespace {

static int run_one_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary | std::ios::ate);
    if (!ifs) {
        std::cerr << "error: cannot open " << path << "\n";
        return 1;
    }
    auto end = ifs.tellg();
    ifs.seekg(0, std::ios::beg);
    std::vector<uint8_t> buf(static_cast<size_t>(end));
    if (!buf.empty())
        ifs.read(reinterpret_cast<char*>(buf.data()), buf.size());
    return LLVMFuzzerTestOneInput(buf.data(), buf.size());
}

static int run_corpus_dir(const std::string& dir) {
    namespace fs = std::filesystem;
    int total = 0, ok = 0;
    for (auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file())
            continue;
        ++total;
        std::cout << "[" << total << "] " << entry.path().filename() << " ... ";
        int ret = run_one_file(entry.path().string());
        if (ret == 0) {
            ++ok;
            std::cout << "OK\n";
        } else {
            std::cout << "FAIL (exit=" << ret << ")\n";
        }
    }
    std::cout << "\nResults: " << ok << "/" << total << " passed\n";
    return (ok == total) ? 0 : 1;
}

} // anonymous namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " <corpus-dir|file>\n";
        return 1;
    }

    const std::string path = argv[1];

    if (std::filesystem::is_directory(path))
        return run_corpus_dir(path);
    else
        return run_one_file(path);
}

#endif  // STANDALONE_FUZZER
#endif  // H2X_FUZZ_DRIVER_HPP