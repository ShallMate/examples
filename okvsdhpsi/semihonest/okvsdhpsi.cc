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

#include "examples/okvsdhpsi/semihonest/okvsdhpsi.h"

#include <cstddef>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "c/blake3.h"
#include "examples/okvsdhpsi/okvs/baxos.h"

#include "yacl/base/int128.h"
#include "yacl/crypto/ecc/ec_point.h"
#include "yacl/crypto/hash/hash_utils.h"
#include "yacl/crypto/rand/rand.h"
#include "yacl/link/context.h"

namespace semihonest {

inline std::vector<uint8_t> HashToFixedSize(size_t bytesize,
                                            const std::vector<uint8_t>& input) {
  std::vector<uint8_t> hashResult(bytesize);

  // Create a new blake3 hasher
  blake3_hasher hasher;
  blake3_hasher_init(&hasher);

  // Write the input bytes to the hash
  blake3_hasher_update(&hasher, input.data(), input.size());

  // Generate the hash with the desired size
  blake3_hasher_finalize(&hasher, hashResult.data(), bytesize);

  return hashResult;
}

inline std::vector<int32_t> GetIntersectionIdx(
    const std::vector<std::vector<uint8_t>>& x,
    const std::vector<std::vector<uint8_t>>& y) {
  // 使用 std::set<std::vector<uint8_t>> 来存储集合
  std::set<std::vector<uint8_t>> set;
  for (const auto& item : x) {
    set.insert(item);
  }
  std::vector<int32_t> ret(y.size(), -1);  // 初始化为 -1
  yacl::parallel_for(0, y.size(), [&](size_t start, size_t end) {
    for (size_t i = start; i < end; ++i) {
      if (set.count(y[i]) != 0) {
        ret[i] = i;
      }
    }
  });
  ret.erase(std::remove(ret.begin(), ret.end(), -1), ret.end());
  return ret;
}

yacl::crypto::EcPoint OkvsDHPsi::GetBasePoint() {
  auto basepoint = ec_->MulBase(sk_);
  return basepoint;
}

void OkvsDHPsi::PointstoBuffer(absl::Span<yc::EcPoint> in,
                               absl::Span<std::uint8_t> buffer) {
  yacl::parallel_for(0, in.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      uint64_t offset = idx * 32;
      ec_->SerializePoint(in[idx], buffer.data() + offset, 32);
    }
  });
}

void OkvsDHPsi::MaskEcPointsD(yc::EcPoint in,
                              absl::Span<std::vector<uint8_t>> out,
                              absl::Span<uint128_t> sks) {
  YACL_ENFORCE(sks.size() == out.size());
  yacl::parallel_for(0, sks.size(), [&](size_t begin, size_t end) {
    for (size_t idx = begin; idx < end; ++idx) {
      std::vector<uint8_t> serialized_point(32);
      ec_->SerializePoint(ec_->Mul(in, yacl::math::MPInt(sks[idx])),
                          serialized_point.data(), 32);
      out[idx] = serialized_point;
    }
  });
}

std::vector<int32_t> OkvsDHPsiRecv(
    const std::shared_ptr<yacl::link::Context>& ctx, std::vector<uint128_t>& y,
    okvs::Baxos baxos, size_t mask_length) {
  OkvsDHPsi recv;
  uint64_t n = y.size();
  size_t okvssize = baxos.size();
  std::vector<uint128_t> ri = yacl::crypto::RandVec<uint128_t>(n);
  std::vector<uint128_t> p(okvssize);
  uint64_t max_point_length = recv.ec_->GetSerializeLength();

  std::vector<uint8_t> basebuffer(max_point_length);
  auto bufbasepoint = ctx->Recv(ctx->PrevRank(), "Receive basepoint");
  YACL_ENFORCE(bufbasepoint.size() ==
               int64_t(max_point_length * sizeof(uint8_t)));
  std::memcpy(basebuffer.data(), bufbasepoint.data(), bufbasepoint.size());
  yc::EcPoint basepoint = recv.ec_->DeserializePoint(
      absl::MakeSpan(basebuffer.data(), max_point_length));
  baxos.Solve(absl::MakeSpan(y), absl::MakeSpan(ri), absl::MakeSpan(p), nullptr,
              8);
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(p.data(), okvssize * sizeof(uint128_t)),
      "Send P");
  std::vector<std::vector<uint8_t>> y_mask(n);
  std::vector<std::vector<uint8_t>> y_str(n);
  recv.MaskEcPointsD(basepoint, absl::MakeSpan(y_mask), absl::MakeSpan(ri));
  yacl::parallel_for(0, n, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      y_str[i] = HashToFixedSize(mask_length, y_mask[i]);
    }
  });

  std::vector<std::vector<uint8_t>> x_str(n, std::vector<uint8_t>(mask_length));
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive x_str");
  YACL_ENFORCE(buf.size() == int64_t(n * mask_length));

  // 使用 yacl::parallel_for 并发复制数据
  yacl::parallel_for(0, n, [&](size_t begin, size_t end) {
    const uint8_t* buf_ptr =
        static_cast<const uint8_t*>(buf.data());  // 转换为 uint8_t* 或 char*
    for (size_t i = begin; i < end; ++i) {
      std::memcpy(x_str[i].data(), buf_ptr + (i * mask_length), mask_length);
    }
  });
  auto z = GetIntersectionIdx(x_str, y_str);
  return z;
}

void OkvsDHPsiSend(const std::shared_ptr<yacl::link::Context>& ctx,
                   std::vector<uint128_t>& x, okvs::Baxos baxos,
                   size_t mask_length) {
  OkvsDHPsi send;
  size_t okvssize = baxos.size();
  size_t n = x.size();
  uint64_t max_point_length = send.ec_->GetSerializeLength();
  yacl::crypto::EcPoint basepoint = send.GetBasePoint();
  std::vector<uint8_t> pointbuffer(max_point_length);
  send.ec_->SerializePoint(basepoint, pointbuffer.data(), pointbuffer.size());
  ctx->SendAsync(
      ctx->NextRank(),
      yacl::ByteContainerView(pointbuffer.data(), pointbuffer.size()),
      "Send basepoint");
  std::vector<uint128_t> p(okvssize);
  auto buf = ctx->Recv(ctx->PrevRank(), "Receive P");
  YACL_ENFORCE(buf.size() == int64_t(okvssize * sizeof(uint128_t)));
  std::memcpy(p.data(), buf.data(), buf.size());
  std::vector<uint128_t> ri(x.size());
  baxos.Decode(absl::MakeSpan(x), absl::MakeSpan(ri), absl::MakeSpan(p), 8);
  std::vector<yacl::math::MPInt> cs(n);
  auto order = send.ec_->GetOrder();
  std::vector<yc::EcPoint> x_points(n);
  std::vector<uint8_t> flat_x_str(n * mask_length);

  yacl::parallel_for(0, n, [&](int64_t beg, int64_t end) {
    for (int64_t i = beg; i < end; ++i) {
      yacl::math::MPInt::Mul(yacl::math::MPInt(ri[i]), send.sk_, &cs[i]);
      cs[i] = cs[i].Mod(order);
      x_points[i] = send.ec_->MulBase(cs[i]);

      std::vector<uint8_t> serialized_point(max_point_length);
      send.ec_->SerializePoint(x_points[i], serialized_point.data(),
                               max_point_length);

      std::vector<uint8_t> hashed_point =
          HashToFixedSize(mask_length, serialized_point);

      std::memcpy(flat_x_str.data() + i * mask_length, hashed_point.data(),
                  mask_length);
    }
  });

  ctx->SendAsync(ctx->NextRank(),
                 yacl::ByteContainerView(flat_x_str.data(), flat_x_str.size()),
                 "Send x_str");
}

};  // namespace semihonest