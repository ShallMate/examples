// Copyright 2023 Ant Group Co., Ltd.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <iostream>
#include <vector>

#include "examples/okvspoint/baxos.h"
#include "spdlog/spdlog.h"

#include "yacl/crypto/rand/rand.h"
#include "yacl/crypto/tools/prg.h"

namespace okvs {

void RunBaxosTest(size_t items_num) {
  size_t bin_size = items_num / 128;
  size_t weight = 3;
  // statistical security parameter
  size_t ssp = 40;

  Baxos baxos;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());

  uint128_t seed;
  prng.Fill(absl::MakeSpan(&seed, 1));

  SPDLOG_INFO("items_num:{}, bin_size:{}", items_num, bin_size);

  baxos.Init(items_num, bin_size, weight, ssp, PaxosParam::DenseType::GF128,
             seed);

  SPDLOG_INFO("baxos.size(): {}", baxos.size());

  std::vector<uint128_t> items(items_num);
  std::vector<uint128_t> values(items_num);
  std::vector<uint128_t> values2(items_num);
  std::vector<uint128_t> p(baxos.size());

  auto start = std::chrono::high_resolution_clock::now();
  prng.Fill(absl::MakeSpan(items.data(), items.size()));
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;
  std::cout << "Time for prng.Fill(items): " << duration.count() << " seconds"
            << std::endl;

  start = std::chrono::high_resolution_clock::now();
  prng.Fill(absl::MakeSpan(values.data(), values.size()));
  end = std::chrono::high_resolution_clock::now();
  duration = end - start;
  std::cout << "Time for prng.Fill(values): " << duration.count() << " seconds"
            << std::endl;

  start = std::chrono::high_resolution_clock::now();
  baxos.Solve(absl::MakeSpan(items), absl::MakeSpan(values), absl::MakeSpan(p));
  end = std::chrono::high_resolution_clock::now();
  duration = end - start;
  std::cout << "Time for baxos.Solve: " << duration.count() << " seconds"
            << std::endl;

  start = std::chrono::high_resolution_clock::now();
  baxos.Decode(absl::MakeSpan(items), absl::MakeSpan(values2),
               absl::MakeSpan(p));
  end = std::chrono::high_resolution_clock::now();
  duration = end - start;
  std::cout << "Time for baxos.Decode: " << duration.count() << " seconds"
            << std::endl;

  if (std::memcmp(values2.data(), values.data(),
                  values.size() * sizeof(uint128_t)) != 0) {
    for (uint64_t i = 0; i < items_num; ++i) {
      if (std::memcmp(&values[i], &values2[i], sizeof(uint128_t)) != 0) {
        std::cerr << "Test failed at index " << i << std::endl;
        return;
      }
    }
  }

  std::cout << "Test passed for items_num: " << items_num << std::endl;
}

void RunPaxostest() {
  // 选择一种 DenseType 类型
  auto dt = PaxosParam::DenseType::Binary;
  SPDLOG_INFO("=== dt:{}",
              dt == PaxosParam::DenseType::Binary ? "binary" : "gf128");
  // 设置参数
  uint64_t n = 1 << 20;
  uint64_t w = 3;
  uint64_t s = 0;
  uint64_t t = 1;

  // 初始化 Paxos 实例
  SPDLOG_INFO("=== tt:{} t:{}", 0, t);  // 由于没有循环，所以 tt 固定为 0
  Paxos<uint32_t> paxos;
  paxos.Init(n, w, 40, dt, yacl::MakeUint128(0, 0));

  // 创建 items 和 values
  std::vector<uint128_t> items(n);
  std::vector<uint128_t> values(n);
  std::vector<uint128_t> values2(n);
  std::vector<uint128_t> p(paxos.size());

  SPDLOG_INFO("n:{}, paxos.size():{}", n, paxos.size());

  // 生成随机数据
  yacl::crypto::Prg<uint128_t> prng(yacl::MakeUint128(0, s));
  prng.Fill(absl::MakeSpan(items.data(), items.size()));
  prng.Fill(absl::MakeSpan(values.data(), values.size()));

  // 设置 Paxos 输入并进行编码解码
  paxos.SetInput(absl::MakeSpan(items));

  SPDLOG_INFO("===encode===");
  paxos.Encode(absl::MakeSpan(values), absl::MakeSpan(p));
  SPDLOG_INFO("===decode===");

  auto start = std::chrono::high_resolution_clock::now();
  paxos.Decode(absl::MakeSpan(items), absl::MakeSpan(values2),
               absl::MakeSpan(p));
  auto end = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end - start;
  std::cout << "Time for baxos.Decode: " << duration.count() << " seconds"
            << std::endl;

  /*
  // 输出编码后的结果
  for (size_t i = 0; i < p.size(); ++i) {
      SPDLOG_INFO("P[{}]:{}", i, (std::ostringstream() <<
  Galois128(p[i])).str());
  }

  // 输出解码后的 values 和 values2
  for (auto &value : values) {
      SPDLOG_INFO("Original value: {}", (std::ostringstream() <<
  Galois128(value)).str());
  }
  for (auto &value : values2) {
      SPDLOG_INFO("Decoded value: {}", (std::ostringstream() <<
  Galois128(value)).str());
  }
  */
  // 检查是否解码正确
  if (std::memcmp(values2.data(), values.data(),
                  sizeof(uint128_t) * values.size()) == 0) {
    std::cout << "Test passed: values match." << std::endl;
  } else {
    std::cout << "Test failed: values do not match." << std::endl;
  }
}

}  // namespace okvs

int main() {
  okvs::RunBaxosTest(1048576);
  // okvs::RunPaxostest();

  return 0;
}
