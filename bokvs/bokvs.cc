
// Copyright 2024 Guowei Ling
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

#include "examples/bokvs/bokvs.h"

#include <immintrin.h>
#include <omp.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <ostream>
#include <vector>

#include "c/blake3.h"
#include "examples/okvs/galois128.h"

#include "yacl/base/int128.h"
#include "yacl/utils/parallel.h"

// 定义一个常量的数组 bitMasks
const uint8_t bitMasks[8] = {
    0x80,  // 1000 0000
    0x40,  // 0100 0000
    0x20,  // 0010 0000
    0x10,  // 0001 0000
    0x08,  // 0000 1000
    0x04,  // 0000 0100
    0x02,  // 0000 0010
    0x01,  // 0000 0001
};

inline bool getBit(uint8_t b, int n) { return (b & bitMasks[n]) > 0; }

inline std::vector<uint8_t> HashToFixedSize(size_t bytesize, uint128_t key) {
  std::vector<uint8_t> hashResult(bytesize);

  // 将 uint128_t 转换为字节数组
  std::uint8_t keyBytes[16];
  std::memcpy(keyBytes, &key, sizeof(key));

  // Create a new blake3 hasher
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Write the key bytes to the hash
  blake3_hasher_update(&hasher, keyBytes, sizeof(keyBytes));

  // Generate the hash with the desired size
  blake3_hasher_finalize(&hasher, hashResult.data(), bytesize);

  return hashResult;
}

inline Row Ro(uint128_t key, uint128_t r, size_t n, uint128_t value) {
  std::vector<uint8_t> row = HashToFixedSize(n, key);
  int64_t pos = BytesToUint128(row) % r;
  int64_t bpos = pos >> 3;
  pos = pos & -8;
  return {pos, bpos, row, value};
}

bool OKVSBK::Encode(std::vector<uint128_t> keys,
                    std::vector<uint128_t> values) {
  auto n = n_;
  auto b = b_;
  auto r = r_;
  auto w = w_;
  std::vector<int64_t> piv(n);
  std::vector<bool> flags(n);
  std::vector<Row> rows(n);
  yacl::parallel_for(0, this->n_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      rows[idx] = Ro(keys[idx], r, b, values[idx]);
    }
  });
  std::sort(rows.begin(), rows.end(),
            [](const Row& a, const Row& b) { return a.pos < b.pos; });
  for (int64_t i = 0; i < n; i++) {
    for (int64_t j = 0; j < w; j++) {
      if (getBit(rows[i].row[static_cast<int>(j >> 3)], j & 7)) {
        piv[i] = j + rows[i].pos;
        flags[i] = true;
        int kk = n;
        for (int64_t k = i + 1; k < n; k++) {
          if (rows[k].pos > piv[i]) {
            kk = k;
            break;
          }
        }
        //#pragma omp parallel for schedule(static, 8)
        for (int64_t idx = i + 1; idx < kk; idx++) {
          int64_t posk = piv[i] - rows[idx].pos;
          if (getBit(rows[idx].row[static_cast<int>(posk / 8)], posk % 8)) {
            int64_t shiftnum = rows[idx].bpos - rows[i].bpos;
#pragma omp simd
            for (int64_t bb = 0; bb < b - shiftnum; bb++) {
              rows[idx].row[bb] ^= rows[i].row[bb + shiftnum];
            }
            rows[idx].value ^= rows[i].value;
          }
        }
        break;
      }
    }
    if (!flags[i]) {
      throw std::runtime_error("encode failed, " + std::to_string(i));
    }
  }
  for (int64_t i = n - 1; i >= 0; i--) {
    uint128_t res = 0;
    int64_t pos = rows[i].pos;
    std::vector<std::uint8_t> row = rows[i].row;
    for (int64_t j = 0; j < w; j++) {
      if (getBit(row[j >> 3], j & 7)) {
        int64_t index = pos + j;
        res = res ^ (this->p_)[index];
      }
    }
    p_[piv[i]] = res ^ rows[i].value;
  }
  return true;
}

void OKVSBK::Decode(std::vector<uint128_t> keys,
                    std::vector<uint128_t>& values) {
  auto b = this->b_;
  auto r = this->r_;
  auto w = this->w_;
  auto p = this->p_;
  yacl::parallel_for(0, this->n_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      std::vector<uint8_t> row = HashToFixedSize(b, keys[idx]);
      int64_t pos = BytesToUint128(row) % r;
      pos = pos & -8;
      for (int64_t j = pos; j < w + pos; j++) {
        if (getBit(row[(j - pos) >> 3], (j - pos) & 7)) {
          values[idx] = values[idx] ^ p[j];
        }
      }
    }
  });
}

void OKVSBK::DecodeOtherP(std::vector<uint128_t> keys,
                          std::vector<uint128_t>& values,
                          std::vector<uint128_t> p) const {
  auto b = this->b_;
  auto r = this->r_;
  auto w = this->w_;
  yacl::parallel_for(0, this->n_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      std::vector<uint8_t> row = HashToFixedSize(b, keys[idx]);
      int64_t pos = BytesToUint128(row) % r;
      pos = pos & -8;
      for (int64_t j = pos; j < w + pos; j++) {
        if (getBit(row[(j - pos) >> 3], (j - pos) & 7)) {
          values[idx] = values[idx] ^ p[j];
        }
      }
    }
  });
}

void OKVSBK::Mul(okvs::Galois128 delta_gf128) {
  auto m = this->m_;
  yacl::parallel_for(0, m, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      this->p_[idx] = (delta_gf128 * this->p_[idx]).get<uint128_t>(0);
    }
  });
}