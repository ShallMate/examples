
#include "examples/bokvspoint/bokvs.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <iostream>
#include <iterator>
#include <ostream>
#include <vector>

#include "examples/okvs/galois128.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/math/mpint/mp_int.h"
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

bool getBit(uint8_t b, int n) { return (b & bitMasks[n]) > 0; }

std::vector<uint8_t> HashToFixedSize(size_t bytesize, yacl::math::MPInt key) {
  std::vector<uint8_t> hashResult(bytesize);
  key.ToBytes(hashResult.data(), bytesize, yacl::Endian::native);
  // std::cout<<bytesize<<std::endl;
  return hashResult;
}

Row Ro(yacl::math::MPInt key, uint128_t r, size_t n, uint128_t value) {
  std::vector<uint8_t> row = HashToFixedSize(n, key);
  int64_t pos = BytesToUint128(row) % r;
  int64_t bpos = pos / 8;
  pos = bpos * 8;
  return {pos, bpos, row, value};
}

bool OKVSBK::Encode(std::vector<yacl::math::MPInt> keys,
                    std::vector<uint32_t> values) {
  auto n = this->n_;
  auto b = this->b_;
  auto r = this->r_;
  auto w = this->w_;
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
      if (getBit(rows[i].row[static_cast<int>(j / 8)], j % 8)) {
        piv[i] = j + rows[i].pos;
        flags[i] = true;
        int kk = n;
        for (int64_t k = i + 1; k < n; k++) {
          if (rows[k].pos > piv[i]) {
            kk = k;
            break;
          }
        }
        yacl::parallel_for(i + 1, kk, [&](int64_t begin, int64_t end) {
          for (int64_t idx = begin; idx < end; ++idx) {
            int64_t posk = piv[i] - rows[idx].pos;
            if (getBit(rows[idx].row[static_cast<int>(posk / 8)], posk % 8)) {
              int64_t shiftnum = rows[idx].bpos - rows[i].bpos;
              for (int64_t bb = 0; bb < b - shiftnum; bb++) {
                rows[idx].row[bb] =
                    rows[idx].row[bb] ^ rows[i].row[bb + shiftnum];
              }
              rows[idx].value = rows[idx].value ^ rows[i].value;
            }
          }
        });
        break;
      }
    }
    if (!flags[i]) {
      throw std::runtime_error("encode failed, " + std::to_string(i));
    }
  }
  for (int64_t i = n - 1; i >= 0; i--) {
    uint128_t res = 0;
    uint128_t pos = rows[i].pos;
    std::vector<std::uint8_t> row = rows[i].row;
    for (int64_t j = 0; j < w; j++) {
      if (getBit(row[j / 8], j % 8)) {
        int64_t index = pos + j;
        res = res ^ (this->p_)[index];
      }
    }
    (this->p_)[piv[i]] = res ^ rows[i].value;
  }
  return true;
}

void OKVSBK::Decode(std::vector<yacl::math::MPInt> keys,
                    std::vector<uint32_t>& values) {
  auto b = this->b_;
  auto r = this->r_;
  auto w = this->w_;
  auto p = this->p_;
  yacl::parallel_for(0, this->n_, [&](int64_t begin, int64_t end) {
    for (int64_t idx = begin; idx < end; ++idx) {
      std::vector<uint8_t> row = HashToFixedSize(b, keys[idx]);
      int64_t pos = BytesToUint128(row) % r;
      pos = (pos / 8) * 8;
      for (int64_t j = pos; j < w + pos; j++) {
        if (getBit(row[(j - pos) / 8], (j - pos) % 8)) {
          values[idx] = values[idx] ^ p[j];
        }
      }
    }
  });
}

void OKVSBK::DecodeSingle(std::vector<yacl::math::MPInt> keys,
                          std::vector<uint32_t>& values) {
  auto b = this->b_;
  auto r = this->r_;
  auto w = this->w_;
  auto p = this->p_;
  for (int64_t idx = 0; idx < this->n_; ++idx) {
    std::vector<uint8_t> row = HashToFixedSize(b, keys[idx]);
    int64_t pos = BytesToUint128(row) % r;
    pos = (pos / 8) * 8;
    for (int64_t j = pos; j < w + pos; j++) {
      if (getBit(row[(j - pos) / 8], (j - pos) % 8)) {
        values[idx] = values[idx] ^ p[j];
      }
    }
  }
}
