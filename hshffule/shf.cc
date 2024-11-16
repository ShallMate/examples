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

#include "examples/hshffule/shf.h"

#include <cstdint>
#include <memory>
#include <vector>

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/ecc/ecc_spi.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/utils/parallel.h"



std::vector<size_t> OsuSend(const std::shared_ptr<yacl::link::Context>& ctx,
                 std::vector<uint128_t>& x) {
  Shuffle sender;
  uint64_t max_point_length = sender.ec_->GetSerializeLength(); 
  size_t n = x.size();
  uint64_t total_length = max_point_length * n;
  std::vector<uint8_t> c1buffer(total_length);
  std::vector<uint8_t> c2buffer(total_length);
  std::vector<yc::EcPoint> c1(n);
  std::vector<yc::EcPoint> c2(n);
  std::vector<size_t> indices(n);
  std::iota(indices.begin(), indices.end(), 0);
  std::random_device rd;
  std::mt19937 g(rd());
  std::shuffle(indices.begin(), indices.end(), g);
  auto bufc1points = ctx->Recv(ctx->PrevRank(), "Receive c1");
  auto bufc2points = ctx->Recv(ctx->PrevRank(), "Receive c2");
  YACL_ENFORCE(bufc1points.size() == int64_t(total_length * sizeof(uint8_t)));
  YACL_ENFORCE(bufc2points.size() == int64_t(total_length * sizeof(uint8_t)));
  std::memcpy(c1buffer.data(), bufc1points.data(), bufc1points.size());
  std::memcpy(c2buffer.data(), bufc2points.data(), bufc2points.size());
  sender.BuffertoPoints(absl::MakeSpan(c1), absl::MakeSpan(c1buffer));
  sender.BuffertoPoints(absl::MakeSpan(c2), absl::MakeSpan(c2buffer));
  sender.MulInputs(absl::MakeSpan(x), absl::MakeSpan(c1), absl::MakeSpan(c2));
  std::vector<yc::EcPoint> newc1(n);
  std::vector<yc::EcPoint> newc2(n);
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      newc1[idx] = c1[indices[idx]];
      newc2[idx] = c2[indices[idx]];
    }
  });
  sender.PointstoBuffer(absl::MakeSpan(newc1), absl::MakeSpan(c1buffer));
  sender.PointstoBuffer(absl::MakeSpan(newc2), absl::MakeSpan(c2buffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(c1buffer.data(), total_length * sizeof(uint8_t)),
      "Send new c1");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(c2buffer.data(), total_length * sizeof(uint8_t)),
      "Send new c2");


  return indices;
}

yacl::dynamic_bitset<uint128_t> OsuRecv(const std::shared_ptr<yacl::link::Context>& ctx,
                                std::vector<uint128_t>& y) {
  Shuffle receiver;
  size_t n = y.size();
  std::vector<yc::EcPoint> c1(n);
  std::vector<yc::EcPoint> c2(n);
  receiver.EncInputs(absl::MakeSpan(y),absl::MakeSpan(c1),absl::MakeSpan(c2));
  uint64_t max_point_length = receiver.ec_->GetSerializeLength();  
  uint64_t total_length = max_point_length * n;
  std::vector<uint8_t> c1buffer(total_length);
  std::vector<uint8_t> c2buffer(total_length);
  receiver.PointstoBuffer(absl::MakeSpan(c1), absl::MakeSpan(c1buffer));
  receiver.PointstoBuffer(absl::MakeSpan(c2), absl::MakeSpan(c2buffer));
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(c1buffer.data(), total_length * sizeof(uint8_t)),
      "Send c1");
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(c2buffer.data(), total_length * sizeof(uint8_t)),
      "Send c2");
  auto bufc1points = ctx->Recv(ctx->PrevRank(), "Receive new c1");
  auto bufc2points = ctx->Recv(ctx->PrevRank(), "Receive new c2");
  YACL_ENFORCE(bufc1points.size() == int64_t(total_length * sizeof(uint8_t)));
  YACL_ENFORCE(bufc2points.size() == int64_t(total_length * sizeof(uint8_t)));
  std::memcpy(c1buffer.data(), bufc1points.data(), bufc1points.size());
  std::memcpy(c2buffer.data(), bufc2points.data(), bufc2points.size());
  receiver.BuffertoPoints(absl::MakeSpan(c1), absl::MakeSpan(c1buffer));
  receiver.BuffertoPoints(absl::MakeSpan(c2), absl::MakeSpan(c2buffer));
  yacl::dynamic_bitset<uint128_t> flags(n);
  receiver.DecInputs(absl::MakeSpan(y),absl::MakeSpan(c1),absl::MakeSpan(c2),flags);
  return flags;

}


void Shuffle::PointstoBuffer(absl::Span<yc::EcPoint> in,
                             absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      ec_->SerializePoint(in[idx], buffer.data() + offset, 32);
    }
  });
}

void Shuffle::BuffertoPoints(absl::Span<yc::EcPoint> in,
                             absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      in[idx] =
          ec_->DeserializePoint(absl::MakeSpan(buffer.data() + offset, 32));
    }
  });
}

void Shuffle::EncInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,absl::Span<yc::EcPoint> c2){
  auto rs = yacl::crypto::RandVec<uint128_t>(in.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto r = yc::MPInt(rs[idx]);
      c1[idx] = ec_->MulBase(r);
      auto mG = ec_->MulBase(yc::MPInt(in[idx]));
      auto rpk = ec_->Mul(pk_, r);
      c2[idx] = ec_->Add(mG, rpk);
    }
  });
}

void Shuffle::DecInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,absl::Span<yc::EcPoint> c2,yacl::dynamic_bitset<uint128_t>& out){
  auto rs = yacl::crypto::RandVec<uint128_t>(in.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto rpk = ec_->Mul(c1[idx], sk_);
      auto mG = ec_->Sub(c2[idx], rpk);
      if(ec_->IsInfinity(mG)){
        out[idx] = true;
      }else{
        out[idx] = false;
      }
    }
  });
}

void Shuffle::MulInputs(absl::Span<uint128_t> in, absl::Span<yc::EcPoint> c1,absl::Span<yc::EcPoint> c2){
  auto rs = yacl::crypto::RandVec<uint128_t>(in.size());
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      auto r = yc::MPInt(rs[idx]);
      auto mg = ec_->MulBase(yc::MPInt(in[idx]));
      //c1[idx] = ec_->Sub(c1[idx],mg);
      c2[idx] = ec_->Sub(c2[idx],mg);
      c1[idx] = ec_->Mul(c1[idx],r);
      c2[idx] = ec_->Mul(c2[idx],r);
    }
  });
}