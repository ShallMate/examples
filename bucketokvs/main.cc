
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <ctime>
#include <iostream>
#include <memory>
#include <set>
#include <tuple>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"
#include "yacl/utils/serialize.h"

// 使用 std::tuple 存储三元组
using Triple = std::tuple<uint32_t, uint32_t, uint32_t>;

inline uint32_t GetSubBytesAsUint32(yacl::Buffer& bytes, size_t start,
                                    size_t end) {
  uint32_t result = 0;
  for (size_t i = start; i < end; ++i) {
    result = (result << 8) | bytes.data<uint8_t>()[i];
  }
  return result;
}

inline Triple sort_triple(Triple t) {
  // 把 tuple 转换为数组，便于排序
  uint32_t arr[3] = {std::get<0>(t), std::get<1>(t), std::get<2>(t)};
  std::sort(arr, arr + 3);
  return std::make_tuple(arr[0], arr[1], arr[2]);
}

// 自定义比较函数，按 hashes 排序
bool compare_triples(const std::tuple<Triple, uint128_t, uint128_t>& a,
                     const std::tuple<Triple, uint128_t, uint128_t>& b) {
  return std::get<0>(a) < std::get<0>(b);
}

void SortHashesAndSyncKeysValues(std::vector<Triple>& hashes,
                                 std::vector<uint128_t>& keys,
                                 std::vector<uint128_t>& values) {
  size_t n = hashes.size();
  std::vector<std::tuple<Triple, uint128_t, uint128_t>> combined(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      combined[i] = std::make_tuple(hashes[i], keys[i], values[i]);
    }
  });
  std::sort(combined.begin(), combined.end(), compare_triples);

  // 将排序后的结果拆分回 hashes、keys 和 values
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      hashes[i] = std::get<0>(combined[i]);
      keys[i] = std::get<1>(combined[i]);
      values[i] = std::get<2>(combined[i]);
    }
  });
}

void GetHashes(std::vector<uint128_t> data, uint32_t cuckoolen,
               std::vector<Triple>& hashes) {
  yacl::parallel_for(0, data.size(), [&](size_t begin, size_t end) {
    for (size_t i = begin; i < end; ++i) {
      auto databyte = yacl::SerializeUint128(data[i]);
      uint32_t a = GetSubBytesAsUint32(databyte, 0, 4) % cuckoolen;
      uint32_t b = GetSubBytesAsUint32(databyte, 4, 8) % cuckoolen;
      uint32_t c = GetSubBytesAsUint32(databyte, 8, 12) % cuckoolen;
      Triple new_triple = std::make_tuple(a, b, c);
      new_triple = sort_triple(new_triple);  // 对三元组排序
      hashes[i] = new_triple;
    }
  });
}

std::vector<uint128_t> CreateRangeItems(size_t begin, size_t size) {
  std::vector<uint128_t> ret;
  for (size_t i = 0; i < size; ++i) {
    ret.push_back(yacl::crypto::Blake3_128(std::to_string(begin + i)));
  }
  return ret;
}

struct Row {
  std::array<uint8_t, 3> hashes;
  std::array<uint32_t, 3> bucketindex;
};

inline Row Ro(Triple rowhashes) {
  std::array<uint8_t, 3> hashes = {0, 0, 0};  // 初始化为 0
  std::array<uint32_t, 3> bucketindex;

  // 计算 bucketindex 和设置对应的位
  bucketindex[0] = (std::get<0>(rowhashes) / 8);
  bucketindex[0] = bucketindex[0] * 8;
  bucketindex[1] = (std::get<1>(rowhashes) / 8);
  bucketindex[1] = bucketindex[1] * 8;
  bucketindex[2] = (std::get<2>(rowhashes) / 8);
  bucketindex[2] = bucketindex[2] * 8;

  // 设置每个hashes数组的第N位为1
  hashes[0] |= (1 << (std::get<0>(rowhashes) % 8));
  hashes[1] |= (1 << (std::get<1>(rowhashes) % 8));
  hashes[2] |= (1 << (std::get<2>(rowhashes) % 8));

  return {hashes, bucketindex};
}

bool Encode(std::vector<Triple> hashes) {
  auto n = hashes.size();
  std::vector<uint32_t> piv(n);
  std::vector<bool> flags(n);
  std::vector<Row> rows(n);
  yacl::parallel_for(0, n, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rows[idx] = Ro(hashes[idx]);
    }
  });
  return true;
}

int main() {
  size_t n = 1 << 20;
  std::vector<uint128_t> keys = CreateRangeItems(0, n);
  std::vector<uint128_t> values = CreateRangeItems(10, n);
  std::vector<Triple> hashes(n);
  uint32_t cuckoolen = static_cast<uint32_t>(n * 1.27);
  GetHashes(keys, cuckoolen, hashes);
  SortHashesAndSyncKeysValues(hashes, keys, values);
  std::vector<uint128_t> p(cuckoolen);
  auto start_time = std::chrono::high_resolution_clock::now();
  Encode(hashes);
  auto end_time = std::chrono::high_resolution_clock::now();
  std::chrono::duration<double> duration = end_time - start_time;
  std::cout << "Execution time: " << duration.count() << " seconds"
            << std::endl;
  return 0;
}