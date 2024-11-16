// Copyright 2024 Guowei LING.
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

#pragma once

#include <memory>
#include <vector>

#include "yacl/base/dynamic_bitset.h"
#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"

namespace yc = yacl::crypto;

class Shuffle {
 public:
  Shuffle() {
    // Use FourQ curve
    ec_ = yc::EcGroupFactory::Instance().Create("FourQ");
    // Generate random key
    yc::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
    pk_ = ec_->MulBase(sk_);
  }

  void EncInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,
                 absl::Span<yc::EcPoint> c2);

  void DecInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,
                 absl::Span<yc::EcPoint> c2,
                 yacl::dynamic_bitset<uint128_t>& out);

  void MulInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,
                 absl::Span<yc::EcPoint> c2);

  void PointstoBuffer(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);

  void BuffertoPoints(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);

 private:
  yc::MPInt sk_;  // secret key
  yc::EcPoint pk_;

 public:
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};

yacl::dynamic_bitset<uint128_t> OsuRecv(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& y);

std::vector<size_t> OsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                            std::vector<uint128_t>& x);
