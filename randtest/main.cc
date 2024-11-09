#include <bitset>
#include <climits>
#include <cstdint>
#include <cstring>
#include <iostream>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/rand/rand.h"

void RunTests() {
  // 1. 测试不同类型的随机数生成函数
  std::cout << "Running RandU64 tests..." << std::endl;
  auto tmp1_u64 = yacl::crypto::FastRandU64();
  auto tmp2_u64 = yacl::crypto::FastRandU64();
  std::cout << "FastRandU64 results: " << tmp1_u64 << " " << tmp2_u64
            << std::endl;

  tmp1_u64 = yacl::crypto::SecureRandU64();
  tmp2_u64 = yacl::crypto::SecureRandU64();
  std::cout << "SecureRandU64 results: " << tmp1_u64 << " " << tmp2_u64
            << std::endl;

  auto tmp1_u128 = yacl::crypto::FastRandU128();
  auto tmp2_u128 = yacl::crypto::FastRandU128();
  std::cout << "FastRandU128 results: " << tmp1_u128 << " " << tmp2_u128
            << std::endl;

  tmp1_u128 = yacl::crypto::SecureRandU128();
  tmp2_u128 = yacl::crypto::SecureRandU128();

  // 2. 测试随机比特集生成
  auto rand_bits = yacl::crypto::SecureRandBits(1000);

  // 3. 测试生成随机向量
  auto vec8 = yacl::crypto::RandVec<uint8_t>(1 << 10);
  auto vec32 = yacl::crypto::RandVec<uint32_t>(1 << 10);
  auto vec64 = yacl::crypto::RandVec<uint64_t>(1 << 10);
  auto vec128 = yacl::crypto::RandVec<uint128_t>(1 << 10);
}

int main() {
  RunTests();
  return 0;
}
