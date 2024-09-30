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

#include "examples/okvspoint/paxos_hash.h"

#include <algorithm>

#include "yacl/base/int128.h"
#include "yacl/utils/platform_utils.h"

namespace okvs {

template <typename IdxType>
void PaxosHash<IdxType>::mod32(uint64_t* vals, uint64_t mod_idx) const {
  auto divider = &mods[mod_idx];
  auto mod_val = mod_vals[mod_idx];

  DoMod32(vals, divider, mod_val);
}

template <typename IdxType>
void PaxosHash<IdxType>::BuildRow32(const absl::Span<uint128_t> hash,
                                    absl::Span<IdxType> rows) const {
    auto rows_ptr = rows.data();
    for (uint64_t k = 0; k < 32; ++k) {
      BuildRow(hash[k], absl::MakeSpan(rows_ptr, weight));
      rows_ptr += weight;
    }
}

template <typename IdxType>
void PaxosHash<IdxType>::BuildRow(const uint128_t& hash,
                                  absl::Span<IdxType> rows) const {
  SPDLOG_DEBUG("weight:{}", weight);

  if (weight == 3) {
    uint32_t* rr = (uint32_t*)&hash;
    auto rr0 = *(uint64_t*)(&rr[0]);
    auto rr1 = *(uint64_t*)(&rr[1]);
    auto rr2 = *(uint64_t*)(&rr[2]);
    rows[0] = (IdxType)(rr0 % sparse_size);
    rows[1] = (IdxType)(rr1 % (sparse_size - 1));
    rows[2] = (IdxType)(rr2 % (sparse_size - 2));

    SPDLOG_DEBUG("rr0:{}, rr1:{}, rr2:{}", rr0, rr1, rr2);
    SPDLOG_DEBUG("rr0:{}, row[1]:{}, row[2]:{}", rows[0], rows[1], rows[2]);

    YACL_ENFORCE(rows[0] < sparse_size);
    YACL_ENFORCE(rows[1] < sparse_size);
    YACL_ENFORCE(rows[2] < sparse_size);

    auto min = std::min<IdxType>(rows[0], rows[1]);
    auto max = rows[0] + rows[1] - min;

    SPDLOG_DEBUG("max:{}, min:{}", max, min);

    if (max == rows[1]) {
      ++rows[1];
      ++max;
    }

    if (rows[2] >= min) {
      ++rows[2];
    }

    if (rows[2] >= max) {
      ++rows[2];
    }

    SPDLOG_DEBUG("max:{}, min:{}", max, min);
    SPDLOG_DEBUG("rr0:{}, row[1]:{}, row[2]:{}", rows[0], rows[1], rows[2]);
  } else {
    Galois128 hh(hash);
    for (uint64_t j = 0; j < weight; ++j) {
      auto modulus = (sparse_size - j);

      hh = hh * hh;

      auto col_idx = hh.get<uint64_t>(0) % modulus;

      auto iter = rows.begin();
      auto end = rows.begin() + j;
      while (iter != end) {
        if (*iter <= col_idx) {
          ++col_idx;
        } else {
          break;
        }
        ++iter;
      }

      while (iter != end) {
        end[0] = end[-1];
        --end;
      }

      *iter = static_cast<IdxType>(col_idx);
    }
  }
}

template <typename IdxType>
void PaxosHash<IdxType>::HashBuildRow32(
    const absl::Span<const uint128_t> in_iter, absl::Span<IdxType> rows,
    absl::Span<uint128_t> hash) const {
  YACL_ENFORCE(in_iter.size() == 32);

  YACL_ENFORCE(rows.size() == 32 * weight);

  aes_crhash->Hash(in_iter, hash);
  BuildRow32(hash, rows);
}

template <typename IdxType>
void PaxosHash<IdxType>::HashBuildRow1(const uint128_t& input,
                                       absl::Span<IdxType> rows,
                                       uint128_t* hash) const {
  YACL_ENFORCE(rows.size() == weight);

  aes_crhash->Hash(absl::MakeSpan(&input, 1), absl::MakeSpan(hash, 1));

  BuildRow(*hash, rows);
}

template struct PaxosHash<uint8_t>;
template struct PaxosHash<uint16_t>;
template struct PaxosHash<uint32_t>;
template struct PaxosHash<uint64_t>;
template struct PaxosHash<uint128_t>;

}  // namespace okvs
