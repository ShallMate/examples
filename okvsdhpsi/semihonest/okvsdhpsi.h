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

#include "examples/okvsdhpsi/okvs/baxos.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/link/link.h"
#include "yacl/utils/parallel.h"

namespace semihonest {
namespace yc = yacl::crypto;

class OkvsDHPsi {
 public:
  OkvsDHPsi() {
    // Use FourQ curve
    ec_ = yc::EcGroupFactory::Instance().Create(/* curve name */ "FourQ");

    // Generate random key
    yc::MPInt::RandomLtN(ec_->GetOrder(), &sk_);
  }
  yacl::crypto::EcPoint GetBasePoint();
  void MaskEcPointsD(yc::EcPoint in, absl::Span<std::vector<uint8_t>> out,
                     absl::Span<uint128_t> sks);
  void PointstoBuffer(absl::Span<yc::EcPoint> in,
                      absl::Span<std::uint8_t> buffer);

  yc::MPInt sk_;                     // secret key
  std::shared_ptr<yc::EcGroup> ec_;  // ec group
};

std::vector<int32_t> OkvsDHPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& y,
    okvs::Baxos baxos, size_t mask_length);

void OkvsDHPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                   std::vector<uint128_t>& x, okvs::Baxos baxos,
                   size_t mask_length);

}  // namespace semihonest