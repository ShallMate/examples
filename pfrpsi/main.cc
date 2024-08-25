#include <cstddef>
#include <iostream>
#include <vector>

#include "examples/pfrpsi/galois128.h"

#include "yacl/base/int128.h"
#include "yacl/kernel/algorithms/silent_vole.h"
#include "yacl/link/test_util.h"
#include "yacl/utils/parallel.h"

using namespace yacl::crypto;
using namespace std;

int main() {

  size_t n = 1048576;
  uint128_t seed;
  yacl::crypto::Prg<uint128_t> prng(yacl::crypto::FastRandU128());
  prng.Fill(absl::MakeSpan(&seed, 1));
  // 创建一个 vector 来存储随机数
  std::vector<uint128_t> A(n);
  std::vector<uint128_t> B(n);
  std::vector<uint128_t> C1(n);
  std::vector<uint128_t> C2(n);


  prng.Fill(absl::MakeSpan(A));
  prng.Fill(absl::MakeSpan(B));
  prng.Fill(absl::MakeSpan(C1));
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      Galois128 delta_a(A[idx]);
      C2[idx] = C1[idx] ^ (delta_a * B[idx]).get<uint128_t>(0);
    }
  });

    // 校验 A[idx] + B[idx] 是否等于 C1[idx] * C2[idx]
  bool is_valid = true;
  for (size_t idx = 0; idx < n; ++idx) {
      uint128_t expected_result = C1[idx] ^ (Galois128(A[idx]) * B[idx]).get<uint128_t>(0);
      if (C2[idx] != expected_result) {
          std::cout << "校验失败: idx = " << idx << std::endl;
          is_valid = false;
          break;
      }
  }

  if (is_valid) {
      std::cout << "校验通过: A + B == C1 * C2" << std::endl;
  } else {
      std::cout << "校验失败: A + B != C1 * C2" << std::endl;
  }

  return 0;


}
