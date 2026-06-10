# h2x — Fuzz 测试目标

本目录包含基于 [libFuzzer](https://llvm.org/docs/LibFuzzer.html) 的 fuzz 测试，
用于检验 h2x HTTP/2 协议库的安全性。

## 测试目标

| 目标           | 测试范围                                              |
|----------------|-------------------------------------------------------|
| `fuzz_frames`  | 所有 HTTP/2 帧解析器 + HPACK 自由函数                  |
| `fuzz_hpack`   | HPACK 整数/字符串/Huffman 解码例程                     |

## 前置依赖

- Clang 编译器（需支持 libFuzzer，clang >= 6.0）
- C++20 支持
- 项目的 Boost / OpenSSL 依赖（与主构建相同）

## 构建

```bash
mkdir build/fuzz && cd build/fuzz

# libFuzzer 模式（Linux/Clang）
cmake -DCMAKE_CXX_COMPILER=clang++ -DENABLE_BUILD_FUZZ=ON ../..
make fuzz_frames fuzz_hpack -j$(nproc)

# 独立模式（macOS/任意编译器，无需 libFuzzer）
cmake -DCMAKE_CXX_COMPILER=clang++ -DENABLE_BUILD_FUZZ=ON -DSTANDALONE_FUZZER=ON ../..
make fuzz_frames fuzz_hpack -j$(nproc)
```

带 ASan + UBSan：

```bash
cmake -DCMAKE_CXX_COMPILER=clang++ \
      -DENABLE_BUILD_FUZZ=ON \
      -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer-no-link,address,undefined" \
      ../..
make fuzz_frames fuzz_hpack -j$(nproc)
```

## 运行

```bash
# 生成种子语料库
python3 fuzz/generate_corpus.py

# libFuzzer 模式（持续 fuzz）
./bin/fuzz_frames -max_len=16384 -jobs=4 fuzz/corpora/fuzz_frames
./bin/fuzz_hpack  -max_len=4096  -jobs=4 fuzz/corpora/fuzz_hpack

# 独立模式（回放语料库）
./bin/fuzz_frames fuzz/corpora/fuzz_frames
./bin/fuzz_hpack  fuzz/corpora/fuzz_hpack
```

### 常用 libFuzzer 参数

- `-max_len=N` — 限制输入大小（帧建议 16384，HPACK 建议 4096）
- `-jobs=N` / `-workers=N` — 并行 fuzz
- `-runs=N` — 限制迭代次数（CI 使用）
- `-dict=fuzz/http2.dict` — HTTP/2 字典（可选提供）
- `artifact_prefix=/tmp/` — 崩溃样本保存路径

## 设计思路

参考了 nghttp2 的 fuzz 方案，这些测试目标将任意字节输入注入到库的解析入口点：

1. **帧解析器**：每种帧类型（`headers_frame`、`data_frame`、`settings_frame` 等）
   都以 fuzzer 提供的字节构造，并强制设置正确的 type 字节，从而让完整的解析逻辑
   得到覆盖。

2. **HPACK**：解码函数（`hpack_unpack_integer`、`hpack_unpack`、`huffman_decode`）
   直接暴露给 fuzzer — 这些函数通过返回码（-1）而非异常来报告错误，因此特别适合
   覆盖率引导的 fuzz 来触及溢出保护和截断边界等极限情况。

3. **种子语料库**：提供了有效的 HTTP/2 帧和 HPACK 数据结构，帮助 fuzzer 快速发现
   有意义的代码路径。

所有帧构造器抛出的异常都会被捕获 — 解析失败是预期行为，不是崩溃。
