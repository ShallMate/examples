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

#include "examples/okvspoint/aes_crhash.h"

#include <vector>

#include "spdlog/spdlog.h"

#include "yacl/utils/parallel.h"

namespace okvs {

namespace {}  // namespace

void AesCrHash::Hash(absl::Span<const uint8_t> plaintext,
                     absl::Span<uint8_t> ciphertext) const {
  std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());
}

void AesCrHash::Hash(absl::Span<const uint128_t> plaintext,
                     absl::Span<uint128_t> ciphertext) const {
  std::copy(plaintext.begin(), plaintext.end(), ciphertext.begin());
}

uint128_t AesCrHash::Hash(uint128_t input) const {
  uint128_t output = input;
  return output;
}

}  // namespace okvs
